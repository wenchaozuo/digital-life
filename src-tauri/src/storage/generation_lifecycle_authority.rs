//! Schema-17 storage-owned generation lifecycle authority primitives.
//!
//! This module deliberately establishes durable authority only.  It neither
//! obtains a vector store nor starts any rebuild, embedding, catch-up, or
//! promotion execution.

use rusqlite::{params, OptionalExtension, TransactionBehavior};

use super::{late_delete_resolution, StorageError, StorageService};

const LEGACY_UNVERIFIED_EMBEDDING_PROFILE: &str = "schema16-profile-unverified";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationAuthorityCommitClassification {
    Committed,
    NotCommitted,
    RecoveryRequired,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationAuthorityCasResult {
    Applied,
    StaleOrConflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RebuildJobRegistrationResult {
    Registered,
    Conflict,
}

/// Input to the sole Schema-17 generation registration transaction.  It does
/// not permit a caller to select lifecycle state or a pointer/epoch mutation.
#[derive(Clone, Debug)]
pub(crate) struct GenerationAuthorityRegistration<'a> {
    pub(crate) generation_id: &'a str,
    pub(crate) descriptor_hash: &'a str,
    pub(crate) dimension: usize,
    pub(crate) descriptor_version: &'a str,
    pub(crate) embedding_profile_id: &'a str,
    pub(crate) create_operation_id: &'a str,
}

#[derive(Clone, Debug)]
pub(crate) struct RebuildJobRegistration<'a> {
    pub(crate) job_id: &'a str,
    pub(crate) request_id: &'a str,
    pub(crate) generation_id: &'a str,
    pub(crate) source_active_generation_id: Option<&'a str>,
    pub(crate) source_active_authority_epoch: Option<i64>,
    pub(crate) candidate_authority_epoch: i64,
}

#[cfg(test)]
thread_local! {
    static REGISTRATION_COMMIT_FAULT: std::cell::Cell<Option<RegistrationCommitFault>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistrationCommitFault {
    BeforeCommit,
    AfterCommitOutcomeUnknown,
}

#[cfg(test)]
pub(crate) fn arm_registration_commit_fault_for_test(fault: RegistrationCommitFault) {
    REGISTRATION_COMMIT_FAULT.with(|next| next.set(Some(fault)));
}

fn valid_nonempty(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512
}

fn lifecycle_error() -> StorageError {
    StorageError::new(
        "GENERATION_LIFECYCLE_AUTHORITY_INVALID",
        "Generation lifecycle authority operation is invalid.",
        false,
    )
}

fn commit_unknown_error() -> StorageError {
    StorageError::new(
        "GENERATION_AUTHORITY_COMMIT_RESULT_UNKNOWN",
        "Generation authority commit result is unknown; classify before any retry.",
        true,
    )
}

fn valid_registration(registration: &GenerationAuthorityRegistration<'_>) -> bool {
    valid_nonempty(registration.generation_id)
        && valid_nonempty(registration.descriptor_hash)
        && registration.dimension > 0
        && valid_nonempty(registration.descriptor_version)
        && valid_nonempty(registration.embedding_profile_id)
        && valid_nonempty(registration.create_operation_id)
}

impl StorageService {
    /// Registers a non-active generation and its immutable Schema-17 authority
    /// records as one transaction.  The store witness is `create_started`, not
    /// `ready`: no external store operation occurs in this group.
    pub(crate) fn register_generation_lifecycle_authority(
        &self,
        registration: GenerationAuthorityRegistration<'_>,
    ) -> Result<(), StorageError> {
        if !valid_registration(&registration) {
            return Err(lifecycle_error());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| lifecycle_error())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)
            .map_err(|_| lifecycle_error())?;
        transaction
            .execute(
                "INSERT INTO memory_vector_generation
                 (generation_id, descriptor_hash, dimension, state, authority_epoch)
                 VALUES (?1, ?2, ?3, 'building', 1)",
                params![
                    registration.generation_id,
                    registration.descriptor_hash,
                    registration.dimension as i64
                ],
            )
            .map_err(|_| lifecycle_error())?;
        transaction
            .execute(
                "INSERT INTO memory_vector_generation_binding
                 (generation_id, descriptor_version, embedding_profile_id, created_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    registration.generation_id,
                    registration.descriptor_version,
                    registration.embedding_profile_id,
                    now
                ],
            )
            .map_err(|_| lifecycle_error())?;
        transaction
            .execute(
                "INSERT INTO memory_vector_generation_store_witness
                 (generation_id, create_operation_id, state, last_error_code, updated_at)
                 VALUES (?1, ?2, 'create_started', NULL, ?3)",
                params![
                    registration.generation_id,
                    registration.create_operation_id,
                    now
                ],
            )
            .map_err(|_| lifecycle_error())?;

        #[cfg(test)]
        if REGISTRATION_COMMIT_FAULT.with(|fault| {
            fault
                .get()
                .is_some_and(|value| value == RegistrationCommitFault::BeforeCommit)
                .then(|| fault.set(None))
                .is_some()
        }) {
            return Err(commit_unknown_error());
        }

        transaction.commit().map_err(|_| lifecycle_error())?;

        #[cfg(test)]
        if REGISTRATION_COMMIT_FAULT.with(|fault| {
            fault
                .get()
                .is_some_and(|value| value == RegistrationCommitFault::AfterCommitOutcomeUnknown)
                .then(|| fault.set(None))
                .is_some()
        }) {
            return Err(commit_unknown_error());
        }
        Ok(())
    }

    /// Read-only exact-witness classification for a registration whose COMMIT
    /// result was lost.  It never retries or repairs an authority write.
    pub(crate) fn classify_generation_registration_commit(
        &self,
        registration: GenerationAuthorityRegistration<'_>,
    ) -> Result<GenerationAuthorityCommitClassification, StorageError> {
        if !valid_registration(&registration) {
            return Err(lifecycle_error());
        }
        let state = self.state()?;
        let exact: Option<i64> = state
            .connection
            .query_row(
                "SELECT 1
                   FROM memory_vector_generation g
                   JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id
                   JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id
                  WHERE g.generation_id=?1 AND g.descriptor_hash=?2 AND g.dimension=?3
                    AND g.state='building' AND g.authority_epoch=1
                    AND b.descriptor_version=?4 AND b.embedding_profile_id=?5
                    AND w.create_operation_id=?6 AND w.state='create_started'",
                params![
                    registration.generation_id,
                    registration.descriptor_hash,
                    registration.dimension as i64,
                    registration.descriptor_version,
                    registration.embedding_profile_id,
                    registration.create_operation_id,
                ],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| lifecycle_error())?;
        if exact.is_some() {
            return Ok(GenerationAuthorityCommitClassification::Committed);
        }
        let witness_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_store_witness
                  WHERE create_operation_id=?1 OR generation_id=?2",
                params![registration.create_operation_id, registration.generation_id],
                |row| row.get(0),
            )
            .map_err(|_| lifecycle_error())?;
        let generation_count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation WHERE generation_id=?1",
                [registration.generation_id],
                |row| row.get(0),
            )
            .map_err(|_| lifecycle_error())?;
        Ok(if witness_count == 0 && generation_count == 0 {
            GenerationAuthorityCommitClassification::NotCommitted
        } else {
            GenerationAuthorityCommitClassification::RecoveryRequired
        })
    }

    /// CASes the singleton pointer to an already-active generation.  This
    /// deliberately does not alter generation state, so it is not promotion.
    pub(crate) fn compare_and_set_active_generation_pointer(
        &self,
        expected_active_generation_id: Option<&str>,
        generation_id: &str,
        expected_authority_epoch: i64,
    ) -> Result<GenerationAuthorityCasResult, StorageError> {
        if !valid_nonempty(generation_id) || expected_authority_epoch < 1 {
            return Err(lifecycle_error());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| lifecycle_error())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)
            .map_err(|_| lifecycle_error())?;
        let changed = transaction
            .execute(
                "UPDATE memory_vector_generation_authority
                    SET active_generation_id=?1, updated_at=?2
                  WHERE singleton=1 AND active_generation_id IS ?3
                    AND EXISTS (
                        SELECT 1 FROM memory_vector_generation
                         WHERE generation_id=?1 AND state='active' AND authority_epoch=?4
                    )",
                params![
                    generation_id,
                    now,
                    expected_active_generation_id,
                    expected_authority_epoch
                ],
            )
            .map_err(|_| lifecycle_error())?;
        transaction.commit().map_err(|_| lifecycle_error())?;
        Ok(if changed == 1 {
            GenerationAuthorityCasResult::Applied
        } else {
            GenerationAuthorityCasResult::StaleOrConflict
        })
    }

    /// Advances only a per-generation authority epoch after an exact preimage
    /// check.  No lifecycle state transition is accepted or performed here.
    pub(crate) fn compare_and_advance_generation_authority_epoch(
        &self,
        generation_id: &str,
        expected_authority_epoch: i64,
    ) -> Result<GenerationAuthorityCasResult, StorageError> {
        if !valid_nonempty(generation_id) || expected_authority_epoch < 1 {
            return Err(lifecycle_error());
        }
        let state = self.state()?;
        let changed = state
            .connection
            .execute(
                "UPDATE memory_vector_generation
                    SET authority_epoch=authority_epoch+1
                  WHERE generation_id=?1 AND authority_epoch=?2
                    AND state IN ('building', 'active', 'retired', 'failed')",
                params![generation_id, expected_authority_epoch],
            )
            .map_err(|_| lifecycle_error())?;
        Ok(if changed == 1 {
            GenerationAuthorityCasResult::Applied
        } else {
            GenerationAuthorityCasResult::StaleOrConflict
        })
    }

    /// Registers the sole nonterminal rebuild-job authority record.  It starts
    /// no work; the enforced `registered` state is only durable intent.
    pub(crate) fn register_generation_rebuild_job(
        &self,
        registration: RebuildJobRegistration<'_>,
    ) -> Result<RebuildJobRegistrationResult, StorageError> {
        if !valid_nonempty(registration.job_id)
            || !valid_nonempty(registration.request_id)
            || !valid_nonempty(registration.generation_id)
            || registration.candidate_authority_epoch < 1
            || registration
                .source_active_authority_epoch
                .is_some_and(|epoch| epoch < 1)
            || registration
                .source_active_generation_id
                .is_some_and(|id| !valid_nonempty(id))
        {
            return Err(lifecycle_error());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| lifecycle_error())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)
            .map_err(|_| lifecycle_error())?;
        let result = transaction.execute(
            "INSERT INTO memory_vector_generation_rebuild_job
             (job_id,request_id,generation_id,source_active_generation_id,source_active_authority_epoch,
              candidate_authority_epoch,status,created_at,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,'registered',?7,?7)",
            params![
                registration.job_id,
                registration.request_id,
                registration.generation_id,
                registration.source_active_generation_id,
                registration.source_active_authority_epoch,
                registration.candidate_authority_epoch,
                now
            ],
        );
        match result {
            Ok(1) => {
                transaction.commit().map_err(|_| lifecycle_error())?;
                Ok(RebuildJobRegistrationResult::Registered)
            }
            Ok(_) | Err(_) => {
                drop(transaction);
                Ok(RebuildJobRegistrationResult::Conflict)
            }
        }
    }
}

pub(super) fn legacy_unverified_embedding_profile() -> &'static str {
    LEGACY_UNVERIFIED_EMBEDDING_PROFILE
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{mpsc, Arc, Barrier},
        thread,
    };

    use rusqlite::{functions::FunctionFlags, Connection};
    use tempfile::TempDir;

    use super::*;

    fn storage_pair(label: &str) -> (TempDir, Arc<StorageService>, Arc<StorageService>) {
        let root = tempfile::Builder::new().prefix(label).tempdir().unwrap();
        let data_root = root.path().join("data");
        let first =
            Arc::new(StorageService::initialize_with_roots(data_root.clone(), None).unwrap());
        let second = Arc::new(StorageService::initialize_with_roots(data_root, None).unwrap());
        (root, first, second)
    }

    fn registration<'a>(
        generation_id: &'a str,
        operation_id: &'a str,
    ) -> GenerationAuthorityRegistration<'a> {
        GenerationAuthorityRegistration {
            generation_id,
            descriptor_hash: "descriptor-a",
            dimension: 8,
            descriptor_version: "descriptor-version-a",
            embedding_profile_id: "profile-a",
            create_operation_id: operation_id,
        }
    }

    #[test]
    fn generation_lifecycle_authority_commit_unknown_before_commit_is_not_committed() {
        let (_root, first, _second) = storage_pair("generation-commit-before");
        arm_registration_commit_fault_for_test(RegistrationCommitFault::BeforeCommit);
        let error = first
            .register_generation_lifecycle_authority(registration("generation-a", "operation-a"))
            .unwrap_err();
        assert_eq!(error.code, "GENERATION_AUTHORITY_COMMIT_RESULT_UNKNOWN");
        assert_eq!(
            first
                .classify_generation_registration_commit(registration(
                    "generation-a",
                    "operation-a"
                ))
                .unwrap(),
            GenerationAuthorityCommitClassification::NotCommitted
        );
    }

    #[test]
    fn generation_lifecycle_authority_commit_unknown_after_real_commit_is_committed_without_replay()
    {
        let (_root, first, _second) = storage_pair("generation-commit-after");
        arm_registration_commit_fault_for_test(RegistrationCommitFault::AfterCommitOutcomeUnknown);
        let error = first
            .register_generation_lifecycle_authority(registration("generation-a", "operation-a"))
            .unwrap_err();
        assert_eq!(error.code, "GENERATION_AUTHORITY_COMMIT_RESULT_UNKNOWN");
        assert_eq!(
            first
                .classify_generation_registration_commit(registration(
                    "generation-a",
                    "operation-a"
                ))
                .unwrap(),
            GenerationAuthorityCommitClassification::Committed
        );
        assert!(first
            .register_generation_lifecycle_authority(registration("generation-a", "operation-a"))
            .is_err());
        let state = first.state().unwrap();
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_store_witness WHERE create_operation_id='operation-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn generation_lifecycle_authority_commit_unknown_mixed_witness_requires_recovery() {
        let (_root, first, _second) = storage_pair("generation-commit-mixed");
        first
            .register_generation_lifecycle_authority(registration("generation-a", "operation-a"))
            .unwrap();
        first
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_generation_store_witness SET state='unverified' WHERE generation_id='generation-a'",
                [],
            )
            .unwrap();
        assert_eq!(
            first
                .classify_generation_registration_commit(registration(
                    "generation-a",
                    "operation-a"
                ))
                .unwrap(),
            GenerationAuthorityCommitClassification::RecoveryRequired
        );
    }

    #[test]
    fn two_connection_cas_active_pointer_has_one_winner() {
        let (_root, first, second) = storage_pair("generation-pointer-race");
        first
            .state()
            .unwrap()
            .connection
            .execute(
                "INSERT INTO memory_vector_generation
                 (generation_id,descriptor_hash,dimension,state,authority_epoch)
                 VALUES ('generation-active','descriptor-active',8,'active',1)",
                [],
            )
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let (sender, receiver) = mpsc::channel();
        for storage in [first, second] {
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            thread::spawn(move || {
                barrier.wait();
                sender
                    .send(storage.compare_and_set_active_generation_pointer(
                        None,
                        "generation-active",
                        1,
                    ))
                    .unwrap();
            });
        }
        drop(sender);
        let results: Vec<_> = receiver.into_iter().map(Result::unwrap).collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == GenerationAuthorityCasResult::Applied)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == GenerationAuthorityCasResult::StaleOrConflict)
                .count(),
            1
        );
    }

    #[test]
    fn two_connection_cas_generation_authority_epoch_has_one_winner() {
        let (_root, first, second) = storage_pair("generation-epoch-race");
        first
            .register_generation_lifecycle_authority(registration("generation-a", "operation-a"))
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let (sender, receiver) = mpsc::channel();
        for storage in [first, second] {
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            thread::spawn(move || {
                barrier.wait();
                sender
                    .send(storage.compare_and_advance_generation_authority_epoch("generation-a", 1))
                    .unwrap();
            });
        }
        drop(sender);
        let results: Vec<_> = receiver.into_iter().map(Result::unwrap).collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == GenerationAuthorityCasResult::Applied)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == GenerationAuthorityCasResult::StaleOrConflict)
                .count(),
            1
        );
    }

    #[test]
    fn two_connection_generation_lifecycle_job_singleton_has_one_winner() {
        let (_root, first, second) = storage_pair("generation-job-race");
        first
            .register_generation_lifecycle_authority(registration("generation-a", "operation-a"))
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let (sender, receiver) = mpsc::channel();
        for (storage, job_id, request_id) in [
            (first, "job-a", "request-a"),
            (second, "job-b", "request-b"),
        ] {
            let barrier = Arc::clone(&barrier);
            let sender = sender.clone();
            thread::spawn(move || {
                barrier.wait();
                sender
                    .send(
                        storage.register_generation_rebuild_job(RebuildJobRegistration {
                            job_id,
                            request_id,
                            generation_id: "generation-a",
                            source_active_generation_id: None,
                            source_active_authority_epoch: None,
                            candidate_authority_epoch: 1,
                        }),
                    )
                    .unwrap();
            });
        }
        drop(sender);
        let results: Vec<_> = receiver.into_iter().map(Result::unwrap).collect();
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == RebuildJobRegistrationResult::Registered)
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == RebuildJobRegistrationResult::Conflict)
                .count(),
            1
        );
    }

    #[test]
    fn generation_lifecycle_writer_fence_rejects_old_writer_authority_mutation() {
        let (_root, first, _second) = storage_pair("generation-writer-fence");
        let database_path = first.state().unwrap().database_path.clone();
        let old_writer = Connection::open(database_path).unwrap();
        old_writer
            .create_scalar_function(
                "digital_life_writer_epoch",
                0,
                FunctionFlags::SQLITE_UTF8
                    | FunctionFlags::SQLITE_DETERMINISTIC
                    | FunctionFlags::SQLITE_INNOCUOUS,
                |_| Ok(0_i64),
            )
            .unwrap();
        let error = old_writer
            .execute(
                "UPDATE memory_vector_generation_authority SET updated_at='old-writer' WHERE singleton=1",
                [],
            )
            .unwrap_err();
        assert!(error.to_string().contains("INCOMPATIBLE_DATABASE_WRITER"));
    }
}
