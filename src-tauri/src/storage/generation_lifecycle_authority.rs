//! Storage-owned Schema-17 generation lifecycle authority.

use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::memory::existing_generation_binding::D9D2_GENERATION_DESCRIPTOR_VERSION;

use super::{late_delete_resolution, StorageError, StorageService};

const LEGACY_UNVERIFIED_EMBEDDING_PROFILE: &str = "schema16-profile-unverified";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationAuthorityCommitClassification {
    Committed,
    NotCommitted,
    RecoveryRequired,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationAuthorityCasResult {
    Applied,
    StaleOrConflict,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GenerationLifecycleState {
    Building,
    Active,
    Failed,
    Retired,
}

#[cfg(test)]
impl GenerationLifecycleState {
    fn sql(self) -> &'static str {
        match self {
            Self::Building => "building",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::Retired => "retired",
        }
    }

    fn allows(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Building, Self::Active)
                | (Self::Building, Self::Failed)
                | (Self::Active, Self::Retired)
        )
    }
}

/// All durable identities required for one atomic generation registration.
#[derive(Clone, Debug)]
pub(crate) struct GenerationAuthorityRegistration<'a> {
    pub(crate) generation_id: &'a str,
    pub(crate) descriptor_hash: &'a str,
    pub(crate) dimension: usize,
    pub(crate) embedding_profile_id: &'a str,
    pub(crate) create_operation_id: &'a str,
    pub(crate) job_id: &'a str,
    pub(crate) request_id: &'a str,
}

#[cfg(test)]
thread_local! {
    static REGISTRATION_FAULT: std::cell::Cell<Option<RegistrationFault>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistrationFault {
    AfterGeneration,
    AfterBinding,
    AfterWitness,
    AfterJob,
    BeforeCommit,
    AfterCommitUnknown,
}

#[cfg(test)]
pub(crate) fn arm_registration_fault_for_test(fault: RegistrationFault) {
    REGISTRATION_FAULT.with(|next| next.set(Some(fault)));
}

fn valid_nonempty(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 512
}

fn invalid() -> StorageError {
    StorageError::new(
        "GENERATION_LIFECYCLE_AUTHORITY_INVALID",
        "Generation lifecycle authority operation is invalid.",
        false,
    )
}

fn commit_unknown() -> StorageError {
    StorageError::new(
        "GENERATION_AUTHORITY_COMMIT_RESULT_UNKNOWN",
        "Generation authority commit result is unknown; classify before any retry.",
        true,
    )
}

fn valid(registration: &GenerationAuthorityRegistration<'_>) -> bool {
    valid_nonempty(registration.generation_id)
        && valid_nonempty(registration.descriptor_hash)
        && registration.dimension > 0
        && valid_nonempty(registration.embedding_profile_id)
        && valid_nonempty(registration.create_operation_id)
        && valid_nonempty(registration.job_id)
        && valid_nonempty(registration.request_id)
}

#[cfg(test)]
fn fail(fault: RegistrationFault) -> bool {
    REGISTRATION_FAULT.with(|next| {
        if next.get() == Some(fault) {
            next.set(None);
            true
        } else {
            false
        }
    })
}

impl StorageService {
    /// Atomically writes generation, immutable binding, create-started witness,
    /// and the initial registered rebuild job. No external I/O occurs here.
    pub(crate) fn register_generation_lifecycle_authority(
        &self,
        registration: GenerationAuthorityRegistration<'_>,
    ) -> Result<(), StorageError> {
        if !valid(&registration) {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| invalid())?;
        // Capture source authority from the singleton pointer while this
        // IMMEDIATE transaction owns the writer slot. A caller cannot select
        // an arbitrary source generation/epoch pair; NULL is the only legal
        // bootstrap world.
        let source: Option<(String, i64)> = transaction
            .query_row(
                "SELECT a.active_generation_id,g.state,g.authority_epoch,
                        EXISTS(SELECT 1 FROM memory_vector_generation WHERE state='active')
                 FROM memory_vector_generation_authority a
                 LEFT JOIN memory_vector_generation g
                   ON g.generation_id=a.active_generation_id
                 WHERE a.singleton=1",
                [],
                |row| {
                    let generation_id: Option<String> = row.get(0)?;
                    let state: Option<String> = row.get(1)?;
                    let epoch: Option<i64> = row.get(2)?;
                    let has_active_generation: bool = row.get(3)?;
                    match generation_id {
                        None if !has_active_generation => Ok(None),
                        None => Err(rusqlite::Error::InvalidQuery),
                        Some(generation_id)
                            if state.as_deref() == Some("active")
                                && epoch.is_some_and(|value| value >= 1) =>
                        {
                            Ok(Some((generation_id, epoch.expect("checked above"))))
                        }
                        Some(_) => Err(rusqlite::Error::InvalidQuery),
                    }
                },
            )
            .map_err(|_| invalid())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)
            .map_err(|_| invalid())?;
        transaction.execute("INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch) VALUES (?1,?2,?3,'building',1)", params![registration.generation_id, registration.descriptor_hash, registration.dimension as i64]).map_err(|_| invalid())?;
        #[cfg(test)]
        if fail(RegistrationFault::AfterGeneration) {
            return Err(invalid());
        }
        transaction.execute("INSERT INTO memory_vector_generation_binding (generation_id,descriptor_version,embedding_profile_id,created_at) VALUES (?1,?2,?3,?4)", params![registration.generation_id, D9D2_GENERATION_DESCRIPTOR_VERSION, registration.embedding_profile_id, now]).map_err(|_| invalid())?;
        #[cfg(test)]
        if fail(RegistrationFault::AfterBinding) {
            return Err(invalid());
        }
        transaction.execute("INSERT INTO memory_vector_generation_store_witness (generation_id,create_operation_id,state,last_error_code,updated_at) VALUES (?1,?2,'create_started',NULL,?3)", params![registration.generation_id, registration.create_operation_id, now]).map_err(|_| invalid())?;
        #[cfg(test)]
        if fail(RegistrationFault::AfterWitness) {
            return Err(invalid());
        }
        let (source_generation_id, source_authority_epoch) = source
            .as_ref()
            .map(|(generation_id, epoch)| (Some(generation_id.as_str()), Some(*epoch)))
            .unwrap_or((None, None));
        transaction.execute("INSERT INTO memory_vector_generation_rebuild_job (job_id,request_id,generation_id,source_active_generation_id,source_active_authority_epoch,candidate_authority_epoch,status,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,1,'registered',?6,?6)", params![registration.job_id, registration.request_id, registration.generation_id, source_generation_id, source_authority_epoch, now]).map_err(|_| invalid())?;
        #[cfg(test)]
        if fail(RegistrationFault::AfterJob) {
            return Err(invalid());
        }
        #[cfg(test)]
        if fail(RegistrationFault::BeforeCommit) {
            return Err(commit_unknown());
        }
        transaction.commit().map_err(|_| commit_unknown())?;
        #[cfg(test)]
        if fail(RegistrationFault::AfterCommitUnknown) {
            return Err(commit_unknown());
        }
        Ok(())
    }

    /// Read-only classification; no retry, repair, or replay is possible here.
    pub(crate) fn classify_generation_registration_commit(
        &self,
        registration: GenerationAuthorityRegistration<'_>,
    ) -> Result<GenerationAuthorityCommitClassification, StorageError> {
        if !valid(&registration) {
            return Err(invalid());
        }
        let state = self.state()?;
        let exact: Option<i64> = state.connection.query_row(
            "SELECT 1 FROM memory_vector_generation g JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id JOIN memory_vector_generation_rebuild_job j ON j.generation_id=g.generation_id WHERE g.generation_id=?1 AND g.descriptor_hash=?2 AND g.dimension=?3 AND g.state='building' AND g.authority_epoch=1 AND b.descriptor_version=?4 AND b.embedding_profile_id=?5 AND w.create_operation_id=?6 AND w.state='create_started' AND j.job_id=?7 AND j.request_id=?8 AND j.candidate_authority_epoch=1 AND j.status='registered'",
            params![registration.generation_id, registration.descriptor_hash, registration.dimension as i64, D9D2_GENERATION_DESCRIPTOR_VERSION, registration.embedding_profile_id, registration.create_operation_id, registration.job_id, registration.request_id],
            |row| row.get(0),
        ).optional().map_err(|_| invalid())?;
        if exact.is_some() {
            return Ok(GenerationAuthorityCommitClassification::Committed);
        }
        let count: i64 = state.connection.query_row(
            "SELECT (SELECT COUNT(*) FROM memory_vector_generation WHERE generation_id=?1) + (SELECT COUNT(*) FROM memory_vector_generation_binding WHERE generation_id=?1) + (SELECT COUNT(*) FROM memory_vector_generation_store_witness WHERE generation_id=?1 OR create_operation_id=?2) + (SELECT COUNT(*) FROM memory_vector_generation_rebuild_job WHERE generation_id=?1 OR job_id=?3 OR request_id=?4)",
            params![registration.generation_id, registration.create_operation_id, registration.job_id, registration.request_id], |row| row.get(0),
        ).map_err(|_| invalid())?;
        Ok(if count == 0 {
            GenerationAuthorityCommitClassification::NotCommitted
        } else {
            GenerationAuthorityCommitClassification::RecoveryRequired
        })
    }

    /// Pointer-only CAS; it requires an active target at the exact epoch.
    #[cfg(test)]
    pub(crate) fn compare_and_set_active_generation_pointer(
        &self,
        expected: Option<&str>,
        generation_id: &str,
        epoch: i64,
    ) -> Result<GenerationAuthorityCasResult, StorageError> {
        if !valid_nonempty(generation_id) || epoch < 1 {
            return Err(invalid());
        }
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| invalid())?;
        let now = late_delete_resolution::authoritative_utc_millis_now_in(&transaction)
            .map_err(|_| invalid())?;
        let changed = transaction.execute("UPDATE memory_vector_generation_authority SET active_generation_id=?1,updated_at=?2 WHERE singleton=1 AND active_generation_id IS ?3 AND EXISTS (SELECT 1 FROM memory_vector_generation WHERE generation_id=?1 AND state='active' AND authority_epoch=?4)", params![generation_id, now, expected, epoch]).map_err(|_| invalid())?;
        transaction.commit().map_err(|_| invalid())?;
        Ok(if changed == 1 {
            GenerationAuthorityCasResult::Applied
        } else {
            GenerationAuthorityCasResult::StaleOrConflict
        })
    }

    /// Applies one exact frozen lifecycle transition and increments epoch once.
    #[cfg(test)]
    pub(crate) fn compare_and_transition_generation_authority(
        &self,
        generation_id: &str,
        expected: GenerationLifecycleState,
        epoch: i64,
        next: GenerationLifecycleState,
    ) -> Result<GenerationAuthorityCasResult, StorageError> {
        if !valid_nonempty(generation_id) || epoch < 1 || !expected.allows(next) {
            return Err(invalid());
        }
        let state = self.state()?;
        let changed = state.connection.execute("UPDATE memory_vector_generation SET state=?4,authority_epoch=authority_epoch+1 WHERE generation_id=?1 AND state=?2 AND authority_epoch=?3", params![generation_id, expected.sql(), epoch, next.sql()]).map_err(|_| invalid())?;
        Ok(if changed == 1 {
            GenerationAuthorityCasResult::Applied
        } else {
            GenerationAuthorityCasResult::StaleOrConflict
        })
    }
}

pub(super) fn legacy_unverified_embedding_profile() -> &'static str {
    LEGACY_UNVERIFIED_EMBEDDING_PROFILE
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::{functions::FunctionFlags, Connection};
    use std::{
        sync::{mpsc, Arc, Barrier},
        thread,
    };
    use tempfile::TempDir;

    fn pair(label: &str) -> (TempDir, Arc<StorageService>, Arc<StorageService>) {
        let root = tempfile::Builder::new().prefix(label).tempdir().unwrap();
        let path = root.path().join("data");
        let first = Arc::new(StorageService::initialize_with_roots(path.clone(), None).unwrap());
        let second = Arc::new(StorageService::initialize_with_roots(path, None).unwrap());
        (root, first, second)
    }
    fn reg<'a>(
        g: &'a str,
        op: &'a str,
        job: &'a str,
        req: &'a str,
    ) -> GenerationAuthorityRegistration<'a> {
        GenerationAuthorityRegistration {
            generation_id: g,
            descriptor_hash: "descriptor-a",
            dimension: 8,
            embedding_profile_id: "profile-a",
            create_operation_id: op,
            job_id: job,
            request_id: req,
        }
    }
    fn count(s: &StorageService, g: &str) -> i64 {
        let state = s.state().unwrap();
        state.connection.query_row("SELECT (SELECT COUNT(*) FROM memory_vector_generation WHERE generation_id=?1)+(SELECT COUNT(*) FROM memory_vector_generation_binding WHERE generation_id=?1)+(SELECT COUNT(*) FROM memory_vector_generation_store_witness WHERE generation_id=?1)+(SELECT COUNT(*) FROM memory_vector_generation_rebuild_job WHERE generation_id=?1)",[g],|r|r.get(0)).unwrap()
    }

    #[test]
    fn generation_lifecycle_authority_registration_atomic_complete() {
        let (_r, a, _b) = pair("generation-atomic");
        a.register_generation_lifecycle_authority(reg("g", "op", "job", "req"))
            .unwrap();
        assert_eq!(count(&a, "g"), 4);
        let state = a.state().unwrap();
        let descriptor_version: String = state
            .connection
            .query_row(
                "SELECT descriptor_version FROM memory_vector_generation_binding WHERE generation_id='g'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(descriptor_version, D9D2_GENERATION_DESCRIPTOR_VERSION);
    }
    #[test]
    fn generation_lifecycle_authority_registration_faults_rollback() {
        for (i, f) in [
            RegistrationFault::AfterGeneration,
            RegistrationFault::AfterBinding,
            RegistrationFault::AfterWitness,
            RegistrationFault::AfterJob,
            RegistrationFault::BeforeCommit,
        ]
        .into_iter()
        .enumerate()
        {
            let (_r, a, _b) = pair("generation-fault");
            let g = format!("g{i}");
            let op = format!("op{i}");
            let job = format!("job{i}");
            let req = format!("req{i}");
            arm_registration_fault_for_test(f);
            assert!(a
                .register_generation_lifecycle_authority(reg(&g, &op, &job, &req))
                .is_err());
            assert_eq!(count(&a, &g), 0);
            assert_eq!(
                a.classify_generation_registration_commit(reg(&g, &op, &job, &req))
                    .unwrap(),
                GenerationAuthorityCommitClassification::NotCommitted
            );
        }
    }
    #[test]
    fn generation_lifecycle_authority_commit_unknown_after_real_commit_is_committed_without_replay()
    {
        let (_r, a, _b) = pair("generation-unknown");
        arm_registration_fault_for_test(RegistrationFault::AfterCommitUnknown);
        assert_eq!(
            a.register_generation_lifecycle_authority(reg("g", "op", "job", "req"))
                .unwrap_err()
                .code,
            "GENERATION_AUTHORITY_COMMIT_RESULT_UNKNOWN"
        );
        assert_eq!(
            a.classify_generation_registration_commit(reg("g", "op", "job", "req"))
                .unwrap(),
            GenerationAuthorityCommitClassification::Committed
        );
        assert_eq!(count(&a, "g"), 4);
    }
    #[test]
    fn generation_lifecycle_authority_commit_unknown_mixed_witness_requires_recovery() {
        let (_r, a, _b) = pair("generation-mixed");
        a.register_generation_lifecycle_authority(reg("g", "op", "job", "req"))
            .unwrap();
        a.state()
            .unwrap()
            .connection
            .execute(
                "DELETE FROM memory_vector_generation_rebuild_job WHERE generation_id='g'",
                [],
            )
            .unwrap();
        assert_eq!(
            a.classify_generation_registration_commit(reg("g", "op", "job", "req"))
                .unwrap(),
            GenerationAuthorityCommitClassification::RecoveryRequired
        );
    }

    #[test]
    fn generation_lifecycle_authority_noncanonical_binding_never_classifies_committed() {
        let (_r, a, _b) = pair("generation-noncanonical-version");
        a.register_generation_lifecycle_authority(reg("g", "op", "job", "req"))
            .unwrap();
        a.state()
            .unwrap()
            .connection
            .execute_batch(
                "DROP TRIGGER memory_vector_generation_binding_immutable_update_guard;
                 UPDATE memory_vector_generation_binding SET descriptor_version='descriptor-v1' WHERE generation_id='g'",
            )
            .unwrap();
        assert_eq!(
            a.classify_generation_registration_commit(reg("g", "op", "job", "req"))
                .unwrap(),
            GenerationAuthorityCommitClassification::RecoveryRequired
        );
    }
    #[test]
    fn generation_lifecycle_transition_guard_enforces_exact_state_machine() {
        let (_r, a, _b) = pair("generation-guard");
        a.register_generation_lifecycle_authority(reg("g", "op", "job", "req"))
            .unwrap();
        {
            let s = a.state().unwrap();
            for sql in ["UPDATE memory_vector_generation SET authority_epoch=2 WHERE generation_id='g'","UPDATE memory_vector_generation SET state='failed' WHERE generation_id='g'","UPDATE memory_vector_generation SET state='failed',authority_epoch=3 WHERE generation_id='g'","UPDATE memory_vector_generation SET state='retired',authority_epoch=2 WHERE generation_id='g'"] {assert!(s.connection.execute(sql,[]).is_err(),"{sql}");}
        }
        assert_eq!(
            a.compare_and_transition_generation_authority(
                "g",
                GenerationLifecycleState::Building,
                1,
                GenerationLifecycleState::Failed
            )
            .unwrap(),
            GenerationAuthorityCasResult::Applied
        );
        let state = a.state().unwrap();
        let row:(String,i64)=state.connection.query_row("SELECT state,authority_epoch FROM memory_vector_generation WHERE generation_id='g'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(row, ("failed".into(), 2));
    }
    #[test]
    fn generation_lifecycle_transition_accepts_active_to_retired() {
        let (_r, a, _b) = pair("generation-retired");
        a.register_generation_lifecycle_authority(reg("g", "op", "job", "req"))
            .unwrap();
        assert_eq!(
            a.compare_and_transition_generation_authority(
                "g",
                GenerationLifecycleState::Building,
                1,
                GenerationLifecycleState::Active
            )
            .unwrap(),
            GenerationAuthorityCasResult::Applied
        );
        assert_eq!(
            a.compare_and_transition_generation_authority(
                "g",
                GenerationLifecycleState::Active,
                2,
                GenerationLifecycleState::Retired
            )
            .unwrap(),
            GenerationAuthorityCasResult::Applied
        );
    }
    #[test]
    fn two_connection_cas_active_pointer_has_one_winner() {
        let (_r, a, b) = pair("pointer-race");
        a.state().unwrap().connection.execute("INSERT INTO memory_vector_generation (generation_id,descriptor_hash,dimension,state,authority_epoch) VALUES ('active','d',8,'active',1)",[]).unwrap();
        let gate = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        for s in [a, b] {
            let gate = gate.clone();
            let tx = tx.clone();
            thread::spawn(move || {
                gate.wait();
                tx.send(s.compare_and_set_active_generation_pointer(None, "active", 1))
                    .unwrap();
            });
        }
        drop(tx);
        let r: Vec<_> = rx.into_iter().map(Result::unwrap).collect();
        assert_eq!(
            r.iter()
                .filter(|x| **x == GenerationAuthorityCasResult::Applied)
                .count(),
            1
        );
        assert_eq!(
            r.iter()
                .filter(|x| **x == GenerationAuthorityCasResult::StaleOrConflict)
                .count(),
            1
        );
    }
    #[test]
    fn two_connection_generation_lifecycle_transition_has_one_winner() {
        let (_r, a, b) = pair("transition-race");
        a.register_generation_lifecycle_authority(reg("g", "op", "job", "req"))
            .unwrap();
        let gate = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        for s in [a.clone(), b] {
            let gate = gate.clone();
            let tx = tx.clone();
            thread::spawn(move || {
                gate.wait();
                tx.send(s.compare_and_transition_generation_authority(
                    "g",
                    GenerationLifecycleState::Building,
                    1,
                    GenerationLifecycleState::Failed,
                ))
                .unwrap();
            });
        }
        drop(tx);
        let r: Vec<_> = rx.into_iter().map(Result::unwrap).collect();
        assert_eq!(
            r.iter()
                .filter(|x| **x == GenerationAuthorityCasResult::Applied)
                .count(),
            1
        );
        assert_eq!(
            r.iter()
                .filter(|x| **x == GenerationAuthorityCasResult::StaleOrConflict)
                .count(),
            1
        );
        let state = a.state().unwrap();
        let row:(String,i64)=state.connection.query_row("SELECT state,authority_epoch FROM memory_vector_generation WHERE generation_id='g'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(row, ("failed".into(), 2));
    }
    #[test]
    fn two_connection_generation_lifecycle_registration_has_one_complete_winner() {
        let (_r, a, b) = pair("registration-race");
        let gate = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        for (s, g, op, job, req) in [
            (a.clone(), "ga", "opa", "joba", "reqa"),
            (b, "gb", "opb", "jobb", "reqb"),
        ] {
            let gate = gate.clone();
            let tx = tx.clone();
            thread::spawn(move || {
                gate.wait();
                tx.send(s.register_generation_lifecycle_authority(reg(g, op, job, req)))
                    .unwrap();
            });
        }
        drop(tx);
        let r: Vec<_> = rx.into_iter().collect();
        assert_eq!(r.iter().filter(|x| x.is_ok()).count(), 1);
        assert_eq!(r.iter().filter(|x| x.is_err()).count(), 1);
        assert!([count(&a, "ga"), count(&a, "gb")].contains(&4));
        assert!([count(&a, "ga"), count(&a, "gb")].contains(&0));
    }
    #[test]
    fn generation_lifecycle_writer_fence_rejects_old_writer_authority_mutation() {
        let (_r, a, _b) = pair("writer-fence");
        let path = a.state().unwrap().database_path.clone();
        let old = Connection::open(path).unwrap();
        old.create_scalar_function(
            "digital_life_writer_epoch",
            0,
            FunctionFlags::SQLITE_UTF8
                | FunctionFlags::SQLITE_DETERMINISTIC
                | FunctionFlags::SQLITE_INNOCUOUS,
            |_| Ok(0_i64),
        )
        .unwrap();
        assert!(old
            .execute(
                "UPDATE memory_vector_generation_authority SET updated_at='old' WHERE singleton=1",
                []
            )
            .unwrap_err()
            .to_string()
            .contains("INCOMPATIBLE_DATABASE_WRITER"));
    }
}
