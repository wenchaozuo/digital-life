//! D29-H5-B process-crash recovery and restart-authority closure.
//!
//! This module is compiled only for the test/integration boundary.  The
//! production capability registry remains empty until a later stage wires a
//! reviewed host caller.  The durable pieces used here are nevertheless
//! production-shaped: H5-A journals stay immutable, H5-B markers are
//! create-new sidecars, and recovery always requires a fresh Host decision.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::d29h4::H4AuthorizedReplaceGrant;
use crate::recovery_journal::{
    target_key_for_prepared_target, RecoveryJournalContext, RecoveryJournalError,
    RecoveryJournalIdentity, RecoveryJournalStore, RecoveryJournalTargetKey, RecoveryJournalV1,
    RecoveryMarkerPersistenceTestFault, RecoveryMarkerState, RecoveryMarkerV1,
    RecoveryTargetLifecycle, RecoveryTransactionBlockReason, RecoveryTransactionId,
    RecoveryTransactionScan, RecoveryTransactionScanItem, RecoveryTransactionSnapshot,
    RecoveryTransactionState, RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES,
};
use crate::workspace_capability::{
    PreparedWorkspaceTargetKind, WorkspaceReadError, WorkspaceRecoveryCommitOutcome,
    WorkspaceRecoveryTestFault, WorkspaceReplaceCancellation, WorkspaceReplaceCommitFence,
    WorkspaceReplaceCommitOutcome, WorkspaceReplaceError, WorkspaceReplaceFenceError,
    WorkspaceReplaceTestFault,
};
use crate::{
    sha256_hex, PreparedWorkspaceTarget, TrustedWorkspaceRoot, VitaAgentRuntimeProfile,
    WorkspaceRelativePath, WorkspaceRootIdentity,
};

pub(crate) const H5_RECOVER_REPLACE_CAPABILITY_ID: &str = "vita.workspace.recover_replace";
pub(crate) const H5_RECOVER_REPLACE_TOOL_NAME: &str = "vita_workspace_recover_replace_file";
const H5_ORIGINAL_REPLACE_CAPABILITY_ID: &str = "vita.workspace.replace_file";
pub(crate) const H5_DESCRIPTOR_RISK_CLASS: &str = "High";
pub(crate) const H5_DESCRIPTOR_APPROVAL_FLOOR: &str = "ExplicitPerAction";
pub(crate) const H5_DESCRIPTOR_SCOPE_REQUIREMENT: &str = "WorkspaceRequired";

const H5_MAX_ID_CHARS: usize = 512;
const H5_GRANT_LIFETIME_MS: u64 = 30_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryActionRequest {
    action_id: String,
    life_id: String,
    task_id: String,
    capability_id: String,
    workspace_root_identity: RecoveryJournalIdentity,
    relative_path: WorkspaceRelativePath,
    target_identity: RecoveryJournalIdentity,
    transaction_id: RecoveryTransactionId,
    journal_integrity_hash: String,
    current_sha256: String,
    current_bytes: usize,
    restore_sha256: String,
    restore_bytes: usize,
    original_replacement_sha256: String,
    authorization_revision: i64,
}

impl RecoveryActionRequest {
    pub(crate) fn from_snapshot(
        snapshot: &RecoveryTransactionSnapshot,
        current: &[u8],
        action_id: &str,
        authorization_revision: i64,
    ) -> Self {
        let journal = snapshot.journal();
        Self {
            action_id: action_id.to_string(),
            life_id: journal.life_id().to_string(),
            task_id: journal.task_id().to_string(),
            capability_id: H5_RECOVER_REPLACE_CAPABILITY_ID.to_string(),
            workspace_root_identity: journal.workspace_root_identity(),
            relative_path: journal.relative_path().clone(),
            target_identity: journal.target_identity(),
            transaction_id: journal.transaction_id().clone(),
            journal_integrity_hash: journal.integrity_hash(),
            current_sha256: sha256_hex(current),
            current_bytes: current.len(),
            restore_sha256: journal.before_sha256(),
            restore_bytes: journal.before_bytes(),
            original_replacement_sha256: journal.replacement_sha256(),
            authorization_revision,
        }
    }

    pub(crate) fn action_id(&self) -> &str {
        &self.action_id
    }

    pub(crate) fn transaction_id(&self) -> &RecoveryTransactionId {
        &self.transaction_id
    }

    pub(crate) fn current_sha256(&self) -> &str {
        &self.current_sha256
    }

    pub(crate) fn current_bytes(&self) -> usize {
        self.current_bytes
    }

    pub(crate) fn authorization_revision(&self) -> i64 {
        self.authorization_revision
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryDenyReason {
    ConfirmationMissing,
    ConfirmationMismatch,
    ConfirmationExpired,
    AuthorizationDisabled,
    StaleRevision,
    RecoveryGrantReplay,
    RecoveryStateInvalid,
    RecoveryBlocked,
    TargetMissing,
    TargetIdentityChanged,
    TargetBusy,
    HardLinkAmbiguous,
    Cancellation,
    NativeFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryExecutionOutcome {
    RecoveryDenied(RecoveryDenyReason),
    RecoveryConflict,
    RecoveredNoOp,
    Recovered,
    RecoveryUnknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryExecutionResult {
    pub outcome: RecoveryExecutionOutcome,
    pub mutation_count: usize,
    pub grant_issued: bool,
    pub marker_persisted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H5RecoveryDisposition {
    None,
    Required,
    MetadataUnknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum H5ReplaceTransactionOutcome {
    Denied { recovery: H5RecoveryDisposition },
    Conflict { recovery: H5RecoveryDisposition },
    Committed,
    CommitUnknown { recovery_required: bool },
    LifecycleUnknown { workspace_mutation_started: bool },
}

#[derive(Debug)]
pub(crate) struct H5ReplaceExecutionResult {
    pub journal: RecoveryJournalV1,
    pub(crate) transaction_outcome: H5ReplaceTransactionOutcome,
    // Native H4 evidence is retained only as private diagnostics.  H5 callers
    // consume `transaction_outcome`, never a split native/marker verdict.
    native_diagnostics: WorkspaceReplaceCommitOutcome,
}

/// A non-Clone runtime bridge produced only from a validated H4 executable
/// replace grant.  Recovery journal bytes deliberately never contain this
/// object or any of its authority material.
pub(crate) struct H5AuthorizedReplaceAction {
    h4_grant: H4AuthorizedReplaceGrant,
}

impl H5AuthorizedReplaceAction {
    pub(crate) fn from_h4_grant(h4_grant: H4AuthorizedReplaceGrant) -> Self {
        Self { h4_grant }
    }
}

static H5_TARGET_ADMISSIONS: OnceLock<Mutex<HashMap<RecoveryJournalTargetKey, ()>>> =
    OnceLock::new();

struct H5TargetAdmissionGuard {
    target: RecoveryJournalTargetKey,
}

impl H5TargetAdmissionGuard {
    fn try_acquire(target: RecoveryJournalTargetKey) -> Option<Self> {
        let admissions = H5_TARGET_ADMISSIONS.get_or_init(|| Mutex::new(HashMap::new()));
        let mut admissions = lock_unpoisoned(admissions);
        if admissions.contains_key(&target) {
            return None;
        }
        admissions.insert(target.clone(), ());
        Some(Self { target })
    }
}

impl Drop for H5TargetAdmissionGuard {
    fn drop(&mut self) {
        if let Some(admissions) = H5_TARGET_ADMISSIONS.get() {
            lock_unpoisoned(admissions).remove(&self.target);
        }
    }
}

struct H5StartedFence<'a> {
    store: &'a RecoveryJournalStore,
    journal: &'a RecoveryJournalV1,
    host_fence: &'a mut dyn WorkspaceReplaceCommitFence,
    started_persistence: StartedPersistenceState,
    started_marker_fault: Option<RecoveryMarkerPersistenceTestFault>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartedPersistenceState {
    NotAttempted,
    VerifiedDurable,
    FailedNeedsReconciliation,
}

impl WorkspaceReplaceCommitFence for H5StartedFence<'_> {
    fn check(&mut self) -> Result<(), WorkspaceReplaceFenceError> {
        if self.started_persistence != StartedPersistenceState::NotAttempted {
            return Err(WorkspaceReplaceFenceError::Error);
        }
        self.host_fence.check()?;
        let persisted = match self.started_marker_fault.take() {
            Some(fault) => self
                .store
                .persist_started_with_test_fault(self.journal, fault),
            None => self.store.persist_started(self.journal),
        };
        match persisted {
            Ok(_) => {
                self.started_persistence = StartedPersistenceState::VerifiedDurable;
                Ok(())
            }
            Err(_) => {
                self.started_persistence = StartedPersistenceState::FailedNeedsReconciliation;
                Err(WorkspaceReplaceFenceError::Error)
            }
        }
    }
}

impl RecoveryExecutionResult {
    fn denied(reason: RecoveryDenyReason, grant_issued: bool) -> Self {
        Self {
            outcome: RecoveryExecutionOutcome::RecoveryDenied(reason),
            mutation_count: 0,
            grant_issued,
            marker_persisted: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryConfirmationEvidence {
    confirmation_id: String,
    action: RecoveryActionRequest,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct RecoveryGrantEvidence {
    grant_id: String,
    confirmation_id: String,
    action: RecoveryActionRequest,
    issued_at_unix_ms: u64,
    expires_at_unix_ms: u64,
    single_use: bool,
    used: bool,
}

pub(crate) trait RecoveryAuthorityPort: Send + Sync {
    fn issue_recovery_grant(
        &self,
        request: &RecoveryActionRequest,
    ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason>;

    fn revalidate_recovery_grant(
        &self,
        grant: &RecoveryGrantEvidence,
        request: &RecoveryActionRequest,
    ) -> Result<(), RecoveryDenyReason>;
}

/// Test/integration Host authority.  Confirmation provisioning is a separate
/// trusted seam and is never synthesized from a recovery request.
pub(crate) struct TestRecoveryAuthority {
    enabled: AtomicBool,
    revision: AtomicI64,
    next_id: AtomicUsize,
    confirmations: Mutex<HashMap<String, RecoveryConfirmationEvidence>>,
    grants: Mutex<HashMap<String, RecoveryGrantEvidence>>,
    trusted_confirmations_provisioned: AtomicUsize,
    request_derived_confirmations: AtomicUsize,
}

impl TestRecoveryAuthority {
    pub(crate) fn new(revision: i64) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(true),
            revision: AtomicI64::new(revision),
            next_id: AtomicUsize::new(0),
            confirmations: Mutex::new(HashMap::new()),
            grants: Mutex::new(HashMap::new()),
            trusted_confirmations_provisioned: AtomicUsize::new(0),
            request_derived_confirmations: AtomicUsize::new(0),
        })
    }

    pub(crate) fn current_revision(&self) -> i64 {
        self.revision.load(Ordering::Acquire)
    }

    pub(crate) fn provision_trusted_confirmation(&self, request: &RecoveryActionRequest) {
        assert_eq!(request.authorization_revision, self.current_revision());
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        let now = unix_millis();
        let confirmation = RecoveryConfirmationEvidence {
            confirmation_id: format!("h5-confirmation-{id}"),
            action: request.clone(),
            issued_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(H5_GRANT_LIFETIME_MS),
        };
        lock_unpoisoned(&self.confirmations).insert(request.action_id.clone(), confirmation);
        self.trusted_confirmations_provisioned
            .fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn disable_test_authorization(&self) -> i64 {
        self.enabled.store(false, Ordering::Release);
        self.revision.fetch_add(1, Ordering::AcqRel) + 1
    }

    pub(crate) fn provenance(&self) -> (usize, usize) {
        (
            self.trusted_confirmations_provisioned
                .load(Ordering::Acquire),
            self.request_derived_confirmations.load(Ordering::Acquire),
        )
    }

    pub(crate) fn grant_count(&self) -> usize {
        lock_unpoisoned(&self.grants).len()
    }
}

impl RecoveryAuthorityPort for TestRecoveryAuthority {
    fn issue_recovery_grant(
        &self,
        request: &RecoveryActionRequest,
    ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(RecoveryDenyReason::AuthorizationDisabled);
        }
        if request.authorization_revision != self.current_revision() {
            return Err(RecoveryDenyReason::StaleRevision);
        }
        let confirmation = lock_unpoisoned(&self.confirmations)
            .get(&request.action_id)
            .cloned()
            .ok_or(RecoveryDenyReason::ConfirmationMissing)?;
        if confirmation.expires_at_unix_ms <= unix_millis() {
            return Err(RecoveryDenyReason::ConfirmationExpired);
        }
        if confirmation.action != *request {
            return Err(RecoveryDenyReason::ConfirmationMismatch);
        }
        let confirmation = lock_unpoisoned(&self.confirmations)
            .remove(&request.action_id)
            .expect("validated recovery confirmation remains available");
        let id = self.next_id.fetch_add(1, Ordering::AcqRel);
        let now = unix_millis();
        let grant = RecoveryGrantEvidence {
            grant_id: format!("h5-grant-{id}"),
            confirmation_id: confirmation.confirmation_id,
            action: request.clone(),
            issued_at_unix_ms: now,
            expires_at_unix_ms: now.saturating_add(H5_GRANT_LIFETIME_MS),
            single_use: true,
            used: false,
        };
        let stored = RecoveryGrantEvidence {
            grant_id: grant.grant_id.clone(),
            confirmation_id: grant.confirmation_id.clone(),
            action: grant.action.clone(),
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            single_use: grant.single_use,
            used: grant.used,
        };
        lock_unpoisoned(&self.grants).insert(stored.grant_id.clone(), stored);
        Ok(grant)
    }

    fn revalidate_recovery_grant(
        &self,
        grant: &RecoveryGrantEvidence,
        request: &RecoveryActionRequest,
    ) -> Result<(), RecoveryDenyReason> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(RecoveryDenyReason::AuthorizationDisabled);
        }
        if request.authorization_revision != self.current_revision()
            || grant.action != *request
            || grant.expires_at_unix_ms <= unix_millis()
        {
            return Err(RecoveryDenyReason::StaleRevision);
        }
        let mut grants = lock_unpoisoned(&self.grants);
        let stored = grants
            .get_mut(&grant.grant_id)
            .ok_or(RecoveryDenyReason::RecoveryGrantReplay)?;
        if stored.used || !stored.single_use || stored != grant {
            return Err(RecoveryDenyReason::RecoveryGrantReplay);
        }
        stored.used = true;
        Ok(())
    }
}

pub(crate) struct H5RecoveryExecutor {
    store: RecoveryJournalStore,
    root: TrustedWorkspaceRoot,
    authority: Arc<dyn RecoveryAuthorityPort>,
    cancelled: Arc<AtomicBool>,
}

impl H5RecoveryExecutor {
    pub(crate) fn new(
        store: RecoveryJournalStore,
        root: TrustedWorkspaceRoot,
        authority: Arc<dyn RecoveryAuthorityPort>,
    ) -> Self {
        Self {
            store,
            root,
            authority,
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub(crate) fn scan(&self) -> Result<RecoveryTransactionScan, RecoveryJournalError> {
        self.store.scan_transactions()
    }

    pub(crate) fn recover(&self, action: RecoveryActionRequest) -> RecoveryExecutionResult {
        self.recover_with_fault(action, None, true)
    }

    #[cfg(windows)]
    pub(crate) fn recover_with_test_fault(
        &self,
        action: RecoveryActionRequest,
        fault: WorkspaceRecoveryTestFault,
    ) -> RecoveryExecutionResult {
        self.recover_with_fault(action, Some(fault), true)
    }

    #[cfg(windows)]
    fn recover_without_recovered_marker_for_test(
        &self,
        action: RecoveryActionRequest,
    ) -> RecoveryExecutionResult {
        self.recover_with_fault(action, None, false)
    }

    fn recover_with_fault(
        &self,
        action: RecoveryActionRequest,
        #[cfg(windows)] fault: Option<WorkspaceRecoveryTestFault>,
        #[cfg(not(windows))] _fault: Option<()>,
        persist_recovered_marker: bool,
    ) -> RecoveryExecutionResult {
        if self.cancelled.load(Ordering::Acquire) {
            return RecoveryExecutionResult::denied(RecoveryDenyReason::Cancellation, false);
        }
        let scan = match self.store.scan_transactions() {
            Ok(scan) => scan,
            Err(_) => {
                return RecoveryExecutionResult::denied(RecoveryDenyReason::RecoveryBlocked, false)
            }
        };
        let snapshot = match scan
            .valid_transactions()
            .find(|snapshot| snapshot.journal().transaction_id() == action.transaction_id())
        {
            Some(snapshot) => snapshot,
            None => {
                return RecoveryExecutionResult::denied(RecoveryDenyReason::RecoveryBlocked, false)
            }
        };
        if snapshot.state() != RecoveryTransactionState::RecoveryRequired {
            return RecoveryExecutionResult::denied(
                match snapshot.state() {
                    RecoveryTransactionState::CommittedTerminal
                    | RecoveryTransactionState::RecoveredTerminal
                    | RecoveryTransactionState::PreparedOnly => {
                        RecoveryDenyReason::RecoveryStateInvalid
                    }
                    RecoveryTransactionState::RecoveryRequired => {
                        RecoveryDenyReason::RecoveryBlocked
                    }
                },
                false,
            );
        }
        let journal = snapshot.journal();
        if !action_binds_journal(&action, journal, self.root.identity()) {
            return RecoveryExecutionResult::denied(RecoveryDenyReason::RecoveryBlocked, false);
        }
        if self.root.verify_named_path_current().is_err() {
            return RecoveryExecutionResult::denied(
                RecoveryDenyReason::TargetIdentityChanged,
                false,
            );
        }
        let prepared_for_observation = match self
            .root
            .prepare_target(journal.relative_path().as_path())
        {
            Ok(prepared) => prepared,
            Err(_) => {
                return RecoveryExecutionResult::denied(RecoveryDenyReason::TargetMissing, false)
            }
        };
        if prepared_for_observation.kind() != PreparedWorkspaceTargetKind::ExistingFile
            && prepared_for_observation.kind() != PreparedWorkspaceTargetKind::Missing
        {
            return RecoveryExecutionResult::denied(
                RecoveryDenyReason::TargetIdentityChanged,
                false,
            );
        }
        if prepared_for_observation.kind() == PreparedWorkspaceTargetKind::Missing {
            return RecoveryExecutionResult::denied(RecoveryDenyReason::TargetMissing, false);
        }
        if prepared_for_observation
            .target_identity()
            .is_none_or(|identity| {
                RecoveryJournalIdentity::from_workspace_identity(identity).ok()
                    != Some(self.root_target_identity(journal))
            })
        {
            return RecoveryExecutionResult::denied(
                RecoveryDenyReason::TargetIdentityChanged,
                false,
            );
        }
        let current = match prepared_for_observation
            .read_existing_file_raw_bounded(RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES)
        {
            Ok(current) => current,
            Err(WorkspaceReadError::InvalidTarget(_)) => {
                return RecoveryExecutionResult::denied(RecoveryDenyReason::TargetMissing, false)
            }
            Err(_) => {
                return RecoveryExecutionResult::denied(RecoveryDenyReason::RecoveryBlocked, false)
            }
        };
        if sha256_hex(&current) != action.current_sha256 || current.len() != action.current_bytes {
            return RecoveryExecutionResult {
                outcome: RecoveryExecutionOutcome::RecoveryConflict,
                mutation_count: 0,
                grant_issued: false,
                marker_persisted: false,
            };
        }
        drop(prepared_for_observation);
        let grant = match self.authority.issue_recovery_grant(&action) {
            Ok(grant) => grant,
            Err(reason) => return RecoveryExecutionResult::denied(reason, false),
        };
        if self.cancelled.load(Ordering::Acquire) {
            return RecoveryExecutionResult::denied(RecoveryDenyReason::Cancellation, true);
        }
        let prepared = match self.root.prepare_target(journal.relative_path().as_path()) {
            Ok(prepared) => prepared,
            Err(_) => {
                return RecoveryExecutionResult::denied(RecoveryDenyReason::TargetMissing, true)
            }
        };
        if prepared.kind() == PreparedWorkspaceTargetKind::Missing {
            return RecoveryExecutionResult::denied(RecoveryDenyReason::TargetMissing, true);
        }
        if prepared.kind() != PreparedWorkspaceTargetKind::ExistingFile
            || prepared.target_identity().is_none_or(|identity| {
                RecoveryJournalIdentity::from_workspace_identity(identity).ok()
                    != Some(self.root_target_identity(journal))
            })
        {
            return RecoveryExecutionResult::denied(
                RecoveryDenyReason::TargetIdentityChanged,
                true,
            );
        }
        let mut fence = RecoveryFence {
            authority: Arc::clone(&self.authority),
            grant,
            action: action.clone(),
            cancelled: Arc::clone(&self.cancelled),
            sent: false,
            denial_reason: None,
        };
        #[cfg(windows)]
        let outcome = match fault {
            Some(fault) => prepared.recover_existing_file_raw_bounded_with_test_fault(
                &action.current_sha256,
                action.current_bytes,
                journal.before_content().as_bytes(),
                &mut fence,
                self.cancelled.as_ref(),
                fault,
            ),
            None => prepared.recover_existing_file_raw_bounded(
                &action.current_sha256,
                action.current_bytes,
                journal.before_content().as_bytes(),
                &mut fence,
                self.cancelled.as_ref(),
            ),
        };
        #[cfg(not(windows))]
        let outcome = {
            let _ = (prepared, journal, action, fault);
            WorkspaceRecoveryCommitOutcome::Denied {
                error: WorkspaceReplaceError::UnavailableOnThisPlatform,
                evidence: Default::default(),
            }
        };
        let fence_reason = fence.denial_reason;
        self.finish_recovery(
            journal,
            outcome,
            true,
            fence_reason,
            persist_recovered_marker,
        )
    }

    fn root_target_identity(&self, journal: &RecoveryJournalV1) -> RecoveryJournalIdentity {
        journal.target_identity()
    }

    fn finish_recovery(
        &self,
        journal: &RecoveryJournalV1,
        outcome: WorkspaceRecoveryCommitOutcome,
        grant_issued: bool,
        fence_reason: Option<RecoveryDenyReason>,
        persist_recovered_marker: bool,
    ) -> RecoveryExecutionResult {
        match outcome {
            WorkspaceRecoveryCommitOutcome::Denied { error, .. } => {
                RecoveryExecutionResult::denied(
                    fence_reason.unwrap_or_else(|| recovery_error_reason(error)),
                    grant_issued,
                )
            }
            WorkspaceRecoveryCommitOutcome::Conflict { .. } => RecoveryExecutionResult {
                outcome: RecoveryExecutionOutcome::RecoveryConflict,
                mutation_count: 0,
                grant_issued,
                marker_persisted: false,
            },
            WorkspaceRecoveryCommitOutcome::NoOp { .. } => {
                if !persist_recovered_marker {
                    return RecoveryExecutionResult {
                        outcome: RecoveryExecutionOutcome::RecoveredNoOp,
                        mutation_count: 0,
                        grant_issued,
                        marker_persisted: false,
                    };
                }
                match self.store.persist_recovered(journal) {
                    Ok(_) => RecoveryExecutionResult {
                        outcome: RecoveryExecutionOutcome::RecoveredNoOp,
                        mutation_count: 0,
                        grant_issued,
                        marker_persisted: true,
                    },
                    Err(_) => RecoveryExecutionResult {
                        outcome: RecoveryExecutionOutcome::RecoveryUnknown,
                        mutation_count: 0,
                        grant_issued,
                        marker_persisted: false,
                    },
                }
            }
            WorkspaceRecoveryCommitOutcome::Recovered { evidence } => {
                let mutation_count = evidence.committed_mutations;
                if !persist_recovered_marker {
                    return RecoveryExecutionResult {
                        outcome: RecoveryExecutionOutcome::Recovered,
                        mutation_count,
                        grant_issued,
                        marker_persisted: false,
                    };
                }
                match self.store.persist_recovered(journal) {
                    Ok(_) => RecoveryExecutionResult {
                        outcome: RecoveryExecutionOutcome::Recovered,
                        mutation_count,
                        grant_issued,
                        marker_persisted: true,
                    },
                    Err(_) => RecoveryExecutionResult {
                        outcome: RecoveryExecutionOutcome::RecoveryUnknown,
                        mutation_count,
                        grant_issued,
                        marker_persisted: false,
                    },
                }
            }
            WorkspaceRecoveryCommitOutcome::RecoveryUnknown { .. } => RecoveryExecutionResult {
                outcome: RecoveryExecutionOutcome::RecoveryUnknown,
                mutation_count: 1,
                grant_issued,
                marker_persisted: false,
            },
        }
    }
}

struct RecoveryFence {
    authority: Arc<dyn RecoveryAuthorityPort>,
    grant: RecoveryGrantEvidence,
    action: RecoveryActionRequest,
    cancelled: Arc<AtomicBool>,
    sent: bool,
    denial_reason: Option<RecoveryDenyReason>,
}

impl WorkspaceReplaceCommitFence for RecoveryFence {
    fn check(&mut self) -> Result<(), WorkspaceReplaceFenceError> {
        if self.sent {
            return Err(WorkspaceReplaceFenceError::Error);
        }
        self.sent = true;
        if self.cancelled.load(Ordering::Acquire) {
            self.denial_reason = Some(RecoveryDenyReason::Cancellation);
            return Err(WorkspaceReplaceFenceError::Cancelled);
        }
        match self
            .authority
            .revalidate_recovery_grant(&self.grant, &self.action)
        {
            Ok(()) => Ok(()),
            Err(reason) => {
                self.denial_reason = Some(reason);
                Err(match reason {
                    RecoveryDenyReason::Cancellation => WorkspaceReplaceFenceError::Cancelled,
                    RecoveryDenyReason::StaleRevision => WorkspaceReplaceFenceError::Stale,
                    _ => WorkspaceReplaceFenceError::Denied,
                })
            }
        }
    }
}

fn action_binds_journal(
    action: &RecoveryActionRequest,
    journal: &RecoveryJournalV1,
    root_identity: WorkspaceRootIdentity,
) -> bool {
    action.life_id == journal.life_id()
        && action.task_id == journal.task_id()
        && action.capability_id == H5_RECOVER_REPLACE_CAPABILITY_ID
        && journal.capability_id() == H5_ORIGINAL_REPLACE_CAPABILITY_ID
        && RecoveryJournalIdentity::from_workspace_identity(root_identity).ok()
            == Some(action.workspace_root_identity)
        && action.workspace_root_identity == journal.workspace_root_identity()
        && action.relative_path == *journal.relative_path()
        && action.target_identity == journal.target_identity()
        && action.transaction_id == *journal.transaction_id()
        && action.journal_integrity_hash == journal.integrity_hash()
        && action.restore_sha256 == journal.before_sha256()
        && action.restore_bytes == journal.before_bytes()
        && action.original_replacement_sha256 == journal.replacement_sha256()
}

fn recovery_error_reason(error: WorkspaceReplaceError) -> RecoveryDenyReason {
    match error {
        WorkspaceReplaceError::TargetMissing => RecoveryDenyReason::TargetMissing,
        WorkspaceReplaceError::TargetBusy => RecoveryDenyReason::TargetBusy,
        WorkspaceReplaceError::TargetIdentityChanged
        | WorkspaceReplaceError::ParentIdentityChanged
        | WorkspaceReplaceError::RootIdentityChanged
        | WorkspaceReplaceError::TargetOutsideRoot
        | WorkspaceReplaceError::ReparseTarget
        | WorkspaceReplaceError::ReparseParent => RecoveryDenyReason::TargetIdentityChanged,
        WorkspaceReplaceError::HardLinkAmbiguous => RecoveryDenyReason::HardLinkAmbiguous,
        WorkspaceReplaceError::CommitFenceCancelled
        | WorkspaceReplaceError::CancellationBeforeMutation => RecoveryDenyReason::Cancellation,
        _ => RecoveryDenyReason::NativeFailure,
    }
}

fn reconcile_started_persistence_failure(
    store: &RecoveryJournalStore,
    journal: &RecoveryJournalV1,
) -> H5ReplaceTransactionOutcome {
    let scan = match store.scan_transactions() {
        Ok(scan) => scan,
        Err(_) => {
            return H5ReplaceTransactionOutcome::LifecycleUnknown {
                workspace_mutation_started: false,
            }
        }
    };

    let state = scan
        .valid_transactions()
        .find(|snapshot| snapshot.journal().transaction_id() == journal.transaction_id())
        .map(RecoveryTransactionSnapshot::state);
    let target_lifecycle = scan.target_lifecycle_for_journal(journal);

    match (state, target_lifecycle) {
        (Some(RecoveryTransactionState::PreparedOnly), RecoveryTargetLifecycle::Clear) => {
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::None,
            }
        }
        (
            Some(
                RecoveryTransactionState::PreparedOnly | RecoveryTransactionState::RecoveryRequired,
            ),
            RecoveryTargetLifecycle::RecoveryRequired,
        ) => H5ReplaceTransactionOutcome::Denied {
            recovery: H5RecoveryDisposition::Required,
        },
        (_, RecoveryTargetLifecycle::Poisoned | RecoveryTargetLifecycle::Ambiguous)
        | (
            Some(
                RecoveryTransactionState::CommittedTerminal
                | RecoveryTransactionState::RecoveredTerminal,
            ),
            _,
        )
        | (Some(RecoveryTransactionState::RecoveryRequired), RecoveryTargetLifecycle::Clear) => {
            H5ReplaceTransactionOutcome::LifecycleUnknown {
                workspace_mutation_started: false,
            }
        }
        _ => H5ReplaceTransactionOutcome::LifecycleUnknown {
            workspace_mutation_started: false,
        },
    }
}

/// Canonical governed H5 entrypoint.  The caller supplies only the non-authority
/// replacement content; every target, context, expected hash, replacement
/// binding, and final Host fence comes from the single-use H4 action.
pub(crate) async fn execute_governed_h5_replace(
    authorized_action: H5AuthorizedReplaceAction,
    replacement_content: String,
    store: RecoveryJournalStore,
    cancellation: Arc<AtomicBool>,
) -> Result<H5ReplaceExecutionResult, RecoveryJournalError> {
    let H5AuthorizedReplaceAction { h4_grant } = authorized_action;
    let root = h4_grant.root().clone();
    let target = h4_grant
        .prepare_bound_target()
        .map_err(|_| RecoveryJournalError::TargetBindingMismatch("H4 target binding rejected"))?;
    let target_key = target_key_for_prepared_target(&target)?;
    let _admission_guard = H5TargetAdmissionGuard::try_acquire(target_key.clone()).ok_or(
        RecoveryJournalError::TransactionBlocked(
            RecoveryTransactionBlockReason::ConcurrentAdmission,
        ),
    )?;
    let scan = store.scan_transactions()?;
    match scan.target_lifecycle(&target_key) {
        RecoveryTargetLifecycle::Clear => {}
        RecoveryTargetLifecycle::RecoveryRequired => {
            return Err(RecoveryJournalError::TransactionBlocked(
                RecoveryTransactionBlockReason::RecoveryRequired,
            ))
        }
        RecoveryTargetLifecycle::Ambiguous => {
            return Err(RecoveryJournalError::TransactionBlocked(
                RecoveryTransactionBlockReason::AmbiguousTarget,
            ))
        }
        RecoveryTargetLifecycle::Poisoned => {
            return Err(RecoveryJournalError::TransactionBlocked(
                RecoveryTransactionBlockReason::PoisonedTarget,
            ))
        }
    }

    let expected_sha256 = h4_grant.expected_sha256().to_string();
    if sha256_hex(replacement_content.as_bytes()) != h4_grant.replacement_sha256()
        || replacement_content.as_bytes().len() != h4_grant.replacement_bytes()
    {
        return Err(RecoveryJournalError::TargetBindingMismatch(
            "replacement content does not match the H4 executable grant",
        ));
    }
    let context = RecoveryJournalContext::new(
        h4_grant.life_id(),
        h4_grant.task_id(),
        h4_grant.capability_id(),
        h4_grant.replacement_sha256(),
        h4_grant.replacement_bytes(),
        h4_grant.tool_call_id(),
        h4_grant.turn_id(),
    )?;
    let runtime = tokio::runtime::Handle::current();
    let mut final_fence = h4_grant.into_final_fence(runtime, Arc::clone(&cancellation));
    let result = tokio::task::spawn_blocking(move || {
        execute_h5b_replace_after_host_pass_internal(
            &store,
            &root,
            target,
            context,
            &expected_sha256,
            &replacement_content,
            cancellation.as_ref(),
            &mut final_fence,
            false,
            None,
            None,
        )
    })
    .await
    .map_err(|_| RecoveryJournalError::TargetBindingMismatch("H5 native worker did not return"))?;
    result
}

// Legacy direct wrapper retained only for focused native/journal tests.  It is
// not the governed H5 entrypoint and is never reachable from production code.
#[cfg(test)]
fn execute_h5b_replace_after_host_pass(
    store: &RecoveryJournalStore,
    root: &TrustedWorkspaceRoot,
    target: PreparedWorkspaceTarget,
    context: crate::recovery_journal::RecoveryJournalContext,
    expected_sha256: &str,
    replacement: &str,
    cancellation: &dyn WorkspaceReplaceCancellation,
    fence: &mut dyn WorkspaceReplaceCommitFence,
) -> Result<H5ReplaceExecutionResult, RecoveryJournalError> {
    execute_h5b_replace_after_host_pass_internal(
        store,
        root,
        target,
        context,
        expected_sha256,
        replacement,
        cancellation,
        fence,
        false,
        None,
        None,
    )
}

#[cfg(all(test, windows))]
fn execute_h5b_replace_after_host_pass_with_test_fault(
    store: &RecoveryJournalStore,
    root: &TrustedWorkspaceRoot,
    target: PreparedWorkspaceTarget,
    context: crate::recovery_journal::RecoveryJournalContext,
    expected_sha256: &str,
    replacement: &str,
    cancellation: &dyn WorkspaceReplaceCancellation,
    fence: &mut dyn WorkspaceReplaceCommitFence,
    fault: WorkspaceReplaceTestFault,
) -> Result<H5ReplaceExecutionResult, RecoveryJournalError> {
    execute_h5b_replace_after_host_pass_internal(
        store,
        root,
        target,
        context,
        expected_sha256,
        replacement,
        cancellation,
        fence,
        false,
        Some(fault),
        None,
    )
}

#[cfg(all(test, windows))]
fn execute_h5b_replace_after_host_pass_with_started_marker_fault(
    store: &RecoveryJournalStore,
    root: &TrustedWorkspaceRoot,
    target: PreparedWorkspaceTarget,
    context: crate::recovery_journal::RecoveryJournalContext,
    expected_sha256: &str,
    replacement: &str,
    cancellation: &dyn WorkspaceReplaceCancellation,
    fence: &mut dyn WorkspaceReplaceCommitFence,
    fault: RecoveryMarkerPersistenceTestFault,
) -> Result<H5ReplaceExecutionResult, RecoveryJournalError> {
    execute_h5b_replace_after_host_pass_internal(
        store,
        root,
        target,
        context,
        expected_sha256,
        replacement,
        cancellation,
        fence,
        false,
        None,
        Some(fault),
    )
}

fn execute_h5b_replace_after_host_pass_internal(
    store: &RecoveryJournalStore,
    root: &TrustedWorkspaceRoot,
    target: PreparedWorkspaceTarget,
    context: crate::recovery_journal::RecoveryJournalContext,
    expected_sha256: &str,
    replacement: &str,
    cancellation: &dyn WorkspaceReplaceCancellation,
    fence: &mut dyn WorkspaceReplaceCommitFence,
    force_commit_marker_failure: bool,
    native_fault: Option<WorkspaceReplaceTestFault>,
    started_marker_fault: Option<RecoveryMarkerPersistenceTestFault>,
) -> Result<H5ReplaceExecutionResult, RecoveryJournalError> {
    if context.capability_id() != H5_ORIGINAL_REPLACE_CAPABILITY_ID
        || context.replacement_sha256() != sha256_hex(replacement.as_bytes())
        || context.replacement_bytes() != replacement.as_bytes().len()
    {
        return Err(RecoveryJournalError::TargetBindingMismatch(
            "H5-B journal context does not bind the original replace operation",
        ));
    }
    root.verify_named_path_current()
        .map_err(RecoveryJournalError::Profile)?;
    let journal = store.create_prepared_for_expected_preimage(&target, context, expected_sha256)?;
    let mut started_fence = H5StartedFence {
        store,
        journal: &journal,
        host_fence: fence,
        started_persistence: StartedPersistenceState::NotAttempted,
        started_marker_fault,
    };
    #[cfg(windows)]
    let outcome = match native_fault {
        Some(fault) => target.replace_existing_file_utf8_bounded_with_test_fault(
            expected_sha256,
            replacement,
            &mut started_fence,
            cancellation,
            fault,
        ),
        None => target.replace_existing_file_utf8_bounded_with_cancellation(
            expected_sha256,
            replacement,
            &mut started_fence,
            cancellation,
        ),
    };
    #[cfg(not(windows))]
    let outcome = {
        let _ = native_fault;
        target.replace_existing_file_utf8_bounded_with_cancellation(
            expected_sha256,
            replacement,
            &mut started_fence,
            cancellation,
        )
    };
    let transaction_outcome = match started_fence.started_persistence {
        StartedPersistenceState::FailedNeedsReconciliation => {
            reconcile_started_persistence_failure(store, &journal)
        }
        StartedPersistenceState::NotAttempted | StartedPersistenceState::VerifiedDurable => {
            let recovery = match started_fence.started_persistence {
                StartedPersistenceState::NotAttempted => H5RecoveryDisposition::None,
                StartedPersistenceState::VerifiedDurable => H5RecoveryDisposition::Required,
                StartedPersistenceState::FailedNeedsReconciliation => {
                    unreachable!("handled by the outer Started reconciliation branch")
                }
            };
            match &outcome {
                WorkspaceReplaceCommitOutcome::Denied { .. } => {
                    H5ReplaceTransactionOutcome::Denied { recovery }
                }
                WorkspaceReplaceCommitOutcome::Conflict { .. } => {
                    H5ReplaceTransactionOutcome::Conflict { recovery }
                }
                WorkspaceReplaceCommitOutcome::CommitUnknown { .. } => {
                    H5ReplaceTransactionOutcome::CommitUnknown {
                        recovery_required: true,
                    }
                }
                WorkspaceReplaceCommitOutcome::Committed { .. } => {
                    let commit_marker = if force_commit_marker_failure {
                        Err(RecoveryJournalError::InjectedFault("commit marker"))
                    } else {
                        store.persist_committed(&journal)
                    };
                    if commit_marker.is_ok() {
                        H5ReplaceTransactionOutcome::Committed
                    } else {
                        H5ReplaceTransactionOutcome::CommitUnknown {
                            recovery_required: true,
                        }
                    }
                }
            }
        }
    };
    Ok(H5ReplaceExecutionResult {
        journal,
        transaction_outcome,
        native_diagnostics: outcome,
    })
}

fn unix_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().min(u64::MAX as u128) as u64
        })
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use std::fs;
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use tempfile::{tempdir, TempDir};

    const BEFORE: &[u8] = b"H5-B before\n";
    const REPLACEMENT: &str = "H5-B replacement\n";
    const H5_HOST_MAX_FRAME_BYTES: usize = 64 * 1024;
    const H5_HOST_IPC_TIMEOUT: Duration = Duration::from_secs(10);

    struct Fixture {
        _app_data: TempDir,
        workspace_dir: TempDir,
        profile: VitaAgentRuntimeProfile,
        store: RecoveryJournalStore,
        root: TrustedWorkspaceRoot,
    }

    impl Fixture {
        fn new() -> Self {
            let app_data = tempdir().expect("H5-B app-data root");
            let workspace_dir = tempdir().expect("H5-B workspace root");
            fs::write(workspace_dir.path().join("target.txt"), BEFORE).unwrap();
            let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
                app_data.path().to_path_buf(),
                workspace_dir.path().to_path_buf(),
            )
            .unwrap();
            profile.ensure_private_runtime_layout().unwrap();
            let store = RecoveryJournalStore::from_runtime_profile(&profile).unwrap();
            let root = profile.workspace_authority().unwrap().clone();
            Self {
                _app_data: app_data,
                workspace_dir,
                profile,
                store,
                root,
            }
        }

        fn target(&self) -> PreparedWorkspaceTarget {
            self.root.prepare_target(Path::new("target.txt")).unwrap()
        }

        fn context(&self) -> crate::recovery_journal::RecoveryJournalContext {
            crate::recovery_journal::RecoveryJournalContext::new(
                "life-h5",
                "task-h5",
                H5_ORIGINAL_REPLACE_CAPABILITY_ID,
                &sha256_hex(REPLACEMENT.as_bytes()),
                REPLACEMENT.len(),
                "tool-h5",
                "turn-h5",
            )
            .unwrap()
        }

        fn prepared_started(&self) -> RecoveryJournalV1 {
            let journal = self
                .store
                .create_prepared(&self.target(), self.context())
                .unwrap();
            self.store.persist_started(&journal).unwrap();
            journal
        }

        fn action(&self, journal: &RecoveryJournalV1) -> RecoveryActionRequest {
            let current = fs::read(self.workspace_dir.path().join("target.txt")).unwrap();
            let snapshot = self
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .find(|candidate| candidate.journal().transaction_id() == journal.transaction_id())
                .cloned()
                .unwrap();
            RecoveryActionRequest::from_snapshot(&snapshot, &current, "recovery-action-h5", 2)
        }

        fn write_replacement(&self) {
            fs::write(
                self.workspace_dir.path().join("target.txt"),
                REPLACEMENT.as_bytes(),
            )
            .unwrap();
        }
    }

    #[test]
    fn same_target_admission_guard_denies_second_holder_without_waiting() {
        let fixture = Fixture::new();
        let target = target_key_for_prepared_target(&fixture.target()).unwrap();
        let first = H5TargetAdmissionGuard::try_acquire(target.clone())
            .expect("first same-target admission");
        assert!(
            H5TargetAdmissionGuard::try_acquire(target.clone()).is_none(),
            "a second canonical admission must fail closed without waiting"
        );
        drop(first);
        assert!(
            H5TargetAdmissionGuard::try_acquire(target).is_some(),
            "the exact target becomes available after the first operation exits"
        );
    }

    #[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H5WireBinding {
        action_id: String,
        life_id: String,
        task_id: String,
        capability_id: String,
        authorization_revision: i64,
        workspace_root_identity: String,
        relative_path: String,
        target_identity: String,
        transaction_id: String,
        journal_integrity_hash: String,
        current_sha256: String,
        current_bytes: u64,
        restore_sha256: String,
        restore_bytes: u64,
        original_replacement_sha256: String,
    }

    #[derive(Clone, Debug, Serialize)]
    #[serde(tag = "operation", rename_all = "snake_case")]
    enum H5HostWireRequest {
        Initialize {
            protocol_version: u8,
            life_id: String,
            task_id: String,
            capability_id: String,
            allowed_workspace_root_identity: String,
        },
        ProvisionRecoveryConfirmation {
            confirmation_id: String,
            #[serde(flatten)]
            binding: H5WireBinding,
        },
        IssueRecoveryGrant {
            #[serde(flatten)]
            binding: H5WireBinding,
        },
        RevalidateRecoveryGrant {
            grant_id: String,
            #[serde(flatten)]
            binding: H5WireBinding,
        },
        DisableAuthorizationForTest {
            life_id: String,
            capability_id: String,
            expected_revision: i64,
        },
        Shutdown {},
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H5ConfirmationWire {
        confirmation_id: String,
        binding: H5WireBinding,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H5GrantWire {
        grant_id: String,
        confirmation_id: String,
        binding: H5WireBinding,
        issued_at_unix_ms: u64,
        expires_at_unix_ms: u64,
        single_use: bool,
        used: bool,
    }

    #[derive(Clone, Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct H5HostResponse {
        operation: String,
        status: String,
        authorization_revision: Option<i64>,
        production_registry_size: Option<usize>,
        test_registry_size: Option<usize>,
        same_sqlite_row: Option<bool>,
        trusted_confirmation: Option<bool>,
        request_derived_confirmation: Option<bool>,
        confirmation: Option<H5ConfirmationWire>,
        confirmation_consumed: Option<bool>,
        recovery_grant: Option<H5GrantWire>,
        denial: Option<String>,
        modifying_syscalls: Option<usize>,
        error: Option<String>,
    }

    enum H5HostCommand {
        Request {
            body: Vec<u8>,
            response: SyncSender<Result<Vec<u8>, String>>,
        },
        Shutdown {
            body: Vec<u8>,
            response: SyncSender<Result<Vec<u8>, String>>,
        },
    }

    struct ProcessIsolatedH5HostProcess {
        commands: std::sync::Mutex<Option<SyncSender<H5HostCommand>>>,
        child: std::sync::Mutex<Child>,
        worker: std::sync::Mutex<Option<JoinHandle<()>>>,
        terminated: AtomicBool,
    }

    impl ProcessIsolatedH5HostProcess {
        fn start(
            repo_root: &Path,
            life_id: String,
            task_id: String,
            allowed_workspace_root_identity: String,
        ) -> Result<Arc<Self>, String> {
            let executable = h5_host_fixture_executable(repo_root)?;
            let mut child = Command::new(executable)
                .current_dir(repo_root)
                .env("CARGO_TERM_COLOR", "never")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("spawn persistent H5 Host fixture: {error}"))?;
            let stdin = child
                .stdin
                .take()
                .ok_or_else(|| "persistent H5 Host fixture stdin unavailable".to_string())?;
            let stdout = child
                .stdout
                .take()
                .ok_or_else(|| "persistent H5 Host fixture stdout unavailable".to_string())?;
            let (sender, receiver) = sync_channel(1);
            let process = Arc::new(Self {
                commands: std::sync::Mutex::new(Some(sender)),
                child: std::sync::Mutex::new(child),
                worker: std::sync::Mutex::new(None),
                terminated: AtomicBool::new(false),
            });
            let worker = thread::spawn(move || h5_host_worker(receiver, stdin, stdout));
            *lock_unpoisoned(&process.worker) = Some(worker);

            let response = process.roundtrip(&H5HostWireRequest::Initialize {
                protocol_version: 1,
                life_id,
                task_id,
                capability_id: H5_RECOVER_REPLACE_CAPABILITY_ID.to_string(),
                allowed_workspace_root_identity,
            });
            let response = match response {
                Ok(response) => response,
                Err(error) => {
                    process.abort();
                    return Err(error);
                }
            };
            let response: H5HostResponse = match serde_json::from_slice(&response) {
                Ok(response) => response,
                Err(_) => {
                    process.abort();
                    return Err("persistent H5 Host initialize response malformed".to_string());
                }
            };
            if response.operation != "initialize"
                || response.status != "ok"
                || response.authorization_revision != Some(2)
                || response.production_registry_size != Some(0)
                || response.test_registry_size != Some(1)
                || response.same_sqlite_row != Some(true)
                || response.trusted_confirmation.is_some()
                || response.request_derived_confirmation.is_some()
                || response.confirmation.is_some()
                || response.confirmation_consumed.is_some()
                || response.recovery_grant.is_some()
                || response.denial.is_some()
                || response.modifying_syscalls.is_some()
                || response.error.is_some()
            {
                process.abort();
                return Err("persistent H5 Host initialize response invalid".to_string());
            }
            Ok(process)
        }

        fn roundtrip(&self, request: &H5HostWireRequest) -> Result<Vec<u8>, String> {
            self.send_command(request, false)
        }

        fn shutdown(&self) -> bool {
            let response = self.send_command(&H5HostWireRequest::Shutdown {}, true);
            let valid_response = response
                .ok()
                .and_then(|body| serde_json::from_slice::<H5HostResponse>(&body).ok())
                .is_some_and(|response| {
                    response.operation == "shutdown"
                        && response.status == "ok"
                        && response.authorization_revision.is_none()
                        && response.production_registry_size.is_none()
                        && response.test_registry_size.is_none()
                        && response.same_sqlite_row.is_none()
                        && response.trusted_confirmation.is_none()
                        && response.request_derived_confirmation.is_none()
                        && response.confirmation.is_none()
                        && response.confirmation_consumed.is_none()
                        && response.recovery_grant.is_none()
                        && response.denial.is_none()
                        && response.modifying_syscalls.is_none()
                        && response.error.is_none()
                });
            self.close_worker(false);
            valid_response
        }

        fn abort(&self) {
            self.close_worker(true);
        }

        fn send_command(
            &self,
            request: &H5HostWireRequest,
            shutdown: bool,
        ) -> Result<Vec<u8>, String> {
            if self.terminated.load(Ordering::Acquire) {
                return Err("persistent H5 Host process is closed".to_string());
            }
            let body = serde_json::to_vec(request)
                .map_err(|_| "H5 Host request serialization failed".to_string())?;
            if body.is_empty() || body.len() > H5_HOST_MAX_FRAME_BYTES {
                return Err("H5 Host request exceeded bounded frame size".to_string());
            }
            let (response_sender, response_receiver) = sync_channel(1);
            let command = if shutdown {
                H5HostCommand::Shutdown {
                    body,
                    response: response_sender,
                }
            } else {
                H5HostCommand::Request {
                    body,
                    response: response_sender,
                }
            };
            let sender = lock_unpoisoned(&self.commands)
                .as_ref()
                .cloned()
                .ok_or_else(|| "persistent H5 Host command channel is closed".to_string())?;
            match sender.try_send(command) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => {
                    self.abort();
                    return Err("persistent H5 Host command channel is busy".to_string());
                }
                Err(TrySendError::Disconnected(_)) => {
                    self.abort();
                    return Err("persistent H5 Host command channel is disconnected".to_string());
                }
            }
            match response_receiver.recv_timeout(H5_HOST_IPC_TIMEOUT) {
                Ok(Ok(body)) => Ok(body),
                Ok(Err(error)) => {
                    self.abort();
                    Err(error)
                }
                Err(_) => {
                    self.abort();
                    Err("persistent H5 Host response timed out".to_string())
                }
            }
        }

        fn close_worker(&self, kill: bool) {
            if self.terminated.swap(true, Ordering::AcqRel) {
                return;
            }
            lock_unpoisoned(&self.commands).take();
            if kill {
                let mut child = lock_unpoisoned(&self.child);
                if child.try_wait().ok().flatten().is_none() {
                    let _ = child.kill();
                }
            }
            if let Some(worker) = lock_unpoisoned(&self.worker).take() {
                let _ = worker.join();
            }
            let mut child = lock_unpoisoned(&self.child);
            if child.try_wait().ok().flatten().is_none() {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }

    impl Drop for ProcessIsolatedH5HostProcess {
        fn drop(&mut self) {
            self.close_worker(true);
        }
    }

    fn h5_host_worker(
        receiver: Receiver<H5HostCommand>,
        mut stdin: ChildStdin,
        mut stdout: ChildStdout,
    ) {
        while let Ok(command) = receiver.recv() {
            let (body, response, shutdown) = match command {
                H5HostCommand::Request { body, response } => (body, response, false),
                H5HostCommand::Shutdown { body, response } => (body, response, true),
            };
            let result =
                write_h5_frame(&mut stdin, &body).and_then(|()| read_h5_frame(&mut stdout));
            let _ = response.send(result);
            if shutdown {
                break;
            }
        }
    }

    fn write_h5_frame(stdin: &mut ChildStdin, body: &[u8]) -> Result<(), String> {
        stdin
            .write_all(&(body.len() as u32).to_be_bytes())
            .and_then(|()| stdin.write_all(body))
            .and_then(|()| stdin.flush())
            .map_err(|_| "H5 Host request frame write failed".to_string())
    }

    fn read_h5_frame(stdout: &mut ChildStdout) -> Result<Vec<u8>, String> {
        let mut length = [0_u8; 4];
        stdout
            .read_exact(&mut length)
            .map_err(|_| "H5 Host response frame length read failed".to_string())?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > H5_HOST_MAX_FRAME_BYTES {
            return Err("H5 Host response frame exceeded its bound".to_string());
        }
        let mut body = vec![0_u8; length];
        stdout
            .read_exact(&mut body)
            .map_err(|_| "H5 Host response frame body read failed".to_string())?;
        Ok(body)
    }

    struct ProcessIsolatedH5RecoveryAuthority {
        process: Arc<ProcessIsolatedH5HostProcess>,
        life_id: String,
        trusted_confirmations_provisioned: AtomicUsize,
        request_derived_confirmations: AtomicUsize,
        disable_at_next_revalidation: AtomicBool,
        sqlite_disable_count: AtomicUsize,
    }

    impl ProcessIsolatedH5RecoveryAuthority {
        fn new(
            allowed_workspace_root_identity: WorkspaceRootIdentity,
            life_id: &str,
            task_id: &str,
        ) -> Result<Arc<Self>, String> {
            let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .ok_or_else(|| "D29-H5 manifest has no repository parent".to_string())?
                .to_path_buf();
            let process = ProcessIsolatedH5HostProcess::start(
                &repo_root,
                life_id.to_string(),
                task_id.to_string(),
                workspace_identity_wire(allowed_workspace_root_identity),
            )?;
            Ok(Arc::new(Self {
                process,
                life_id: life_id.to_string(),
                trusted_confirmations_provisioned: AtomicUsize::new(0),
                request_derived_confirmations: AtomicUsize::new(0),
                disable_at_next_revalidation: AtomicBool::new(false),
                sqlite_disable_count: AtomicUsize::new(0),
            }))
        }

        fn provision_trusted_confirmation(
            &self,
            request: &RecoveryActionRequest,
        ) -> Result<(), String> {
            let response =
                self.process
                    .roundtrip(&H5HostWireRequest::ProvisionRecoveryConfirmation {
                        confirmation_id: format!("d29h5-confirmation-{}", request.action_id()),
                        binding: h5_wire_binding(request),
                    })?;
            let response: H5HostResponse = parse_h5_response(response, "confirmation")?;
            if response.operation != "provision_recovery_confirmation"
                || response.status != "ok"
                || response.trusted_confirmation != Some(true)
                || response.request_derived_confirmation != Some(false)
                || response.authorization_revision.is_some()
                || response.production_registry_size.is_some()
                || response.test_registry_size.is_some()
                || response.same_sqlite_row.is_some()
                || response.confirmation.is_some()
                || response.confirmation_consumed.is_some()
                || response.recovery_grant.is_some()
                || response.denial.is_some()
                || response.modifying_syscalls.is_some()
                || response.error.is_some()
            {
                return Err("H5 Host confirmation response shape invalid".to_string());
            }
            self.trusted_confirmations_provisioned
                .fetch_add(1, Ordering::AcqRel);
            Ok(())
        }

        fn arm_disable_at_next_revalidation(&self) {
            self.disable_at_next_revalidation
                .store(true, Ordering::Release);
        }

        fn sqlite_disable_count(&self) -> usize {
            self.sqlite_disable_count.load(Ordering::Acquire)
        }

        fn provenance(&self) -> (usize, usize) {
            (
                self.trusted_confirmations_provisioned
                    .load(Ordering::Acquire),
                self.request_derived_confirmations.load(Ordering::Acquire),
            )
        }

        fn disable_authorization_for_test(&self, expected_revision: i64) -> Result<i64, String> {
            let response =
                self.process
                    .roundtrip(&H5HostWireRequest::DisableAuthorizationForTest {
                        life_id: self.life_id.clone(),
                        capability_id: H5_RECOVER_REPLACE_CAPABILITY_ID.to_string(),
                        expected_revision,
                    })?;
            let response: H5HostResponse = parse_h5_response(response, "disable")?;
            let revision = response.authorization_revision.ok_or_else(|| {
                "H5 Host disable response omitted authorization revision".to_string()
            })?;
            if response.operation != "disable_authorization_for_test"
                || response.status != "ok"
                || revision != expected_revision + 1
                || response.same_sqlite_row != Some(true)
                || response.production_registry_size.is_some()
                || response.test_registry_size.is_some()
                || response.trusted_confirmation.is_some()
                || response.request_derived_confirmation.is_some()
                || response.confirmation.is_some()
                || response.confirmation_consumed.is_some()
                || response.recovery_grant.is_some()
                || response.denial.is_some()
                || response.modifying_syscalls.is_some()
                || response.error.is_some()
            {
                return Err("H5 Host disable response shape invalid".to_string());
            }
            self.sqlite_disable_count.fetch_add(1, Ordering::AcqRel);
            Ok(revision)
        }

        fn shutdown(&self) -> bool {
            self.process.shutdown()
        }
    }

    impl RecoveryAuthorityPort for ProcessIsolatedH5RecoveryAuthority {
        fn issue_recovery_grant(
            &self,
            request: &RecoveryActionRequest,
        ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason> {
            let response = self
                .process
                .roundtrip(&H5HostWireRequest::IssueRecoveryGrant {
                    binding: h5_wire_binding(request),
                })
                .map_err(|_| RecoveryDenyReason::NativeFailure)?;
            let response: H5HostResponse = match parse_h5_response(response, "issue") {
                Ok(response) => response,
                Err(_) => {
                    self.process.abort();
                    return Err(RecoveryDenyReason::NativeFailure);
                }
            };
            if response.status == "denied" {
                return Err(
                    parse_h5_denied_response(&response, "issue_recovery_grant", false)
                        .map_err(|_| RecoveryDenyReason::NativeFailure)?,
                );
            }
            if response.operation != "issue_recovery_grant"
                || response.status != "ok"
                || response.authorization_revision != Some(request.authorization_revision())
                || response.production_registry_size != Some(0)
                || response.test_registry_size != Some(1)
                || response.confirmation_consumed != Some(true)
                || response.denial.is_some()
                || response.modifying_syscalls.is_some()
                || response.error.is_some()
                || response.trusted_confirmation.is_some()
                || response.request_derived_confirmation.is_some()
            {
                self.process.abort();
                return Err(RecoveryDenyReason::NativeFailure);
            }
            let confirmation = match response.confirmation {
                Some(confirmation) => confirmation,
                None => {
                    self.process.abort();
                    return Err(RecoveryDenyReason::NativeFailure);
                }
            };
            let wire_grant = match response.recovery_grant {
                Some(grant) => grant,
                None => {
                    self.process.abort();
                    return Err(RecoveryDenyReason::NativeFailure);
                }
            };
            if confirmation.binding != h5_wire_binding(request)
                || confirmation.confirmation_id != wire_grant.confirmation_id
                || !valid_h5_id(&confirmation.confirmation_id)
                || confirmation.expires_at_unix_ms <= confirmation.issued_at_unix_ms
            {
                self.process.abort();
                return Err(RecoveryDenyReason::NativeFailure);
            }
            parse_h5_grant(wire_grant, request, false, &confirmation.confirmation_id).map_err(
                |_| {
                    self.process.abort();
                    RecoveryDenyReason::NativeFailure
                },
            )
        }

        fn revalidate_recovery_grant(
            &self,
            grant: &RecoveryGrantEvidence,
            request: &RecoveryActionRequest,
        ) -> Result<(), RecoveryDenyReason> {
            if self
                .disable_at_next_revalidation
                .swap(false, Ordering::AcqRel)
            {
                self.disable_authorization_for_test(grant.action.authorization_revision())
                    .map_err(|_| RecoveryDenyReason::NativeFailure)?;
            }
            let response = self
                .process
                .roundtrip(&H5HostWireRequest::RevalidateRecoveryGrant {
                    grant_id: grant.grant_id.clone(),
                    binding: h5_wire_binding(request),
                })
                .map_err(|_| RecoveryDenyReason::NativeFailure)?;
            let response: H5HostResponse = match parse_h5_response(response, "revalidate") {
                Ok(response) => response,
                Err(_) => {
                    self.process.abort();
                    return Err(RecoveryDenyReason::NativeFailure);
                }
            };
            if response.status == "denied" {
                return Err(
                    parse_h5_denied_response(&response, "revalidate_recovery_grant", true)
                        .map_err(|_| RecoveryDenyReason::NativeFailure)?,
                );
            }
            if response.operation != "revalidate_recovery_grant"
                || response.status != "ok"
                || response.authorization_revision != Some(request.authorization_revision())
                || response.confirmation.is_some()
                || response.confirmation_consumed.is_some()
                || response.denial.is_some()
                || response.production_registry_size.is_some()
                || response.test_registry_size.is_some()
                || response.trusted_confirmation.is_some()
                || response.request_derived_confirmation.is_some()
                || response.modifying_syscalls.is_some()
                || response.error.is_some()
            {
                self.process.abort();
                return Err(RecoveryDenyReason::NativeFailure);
            }
            let wire_grant = match response.recovery_grant {
                Some(grant) => grant,
                None => {
                    self.process.abort();
                    return Err(RecoveryDenyReason::NativeFailure);
                }
            };
            let parsed = parse_h5_grant(wire_grant, request, true, &grant.confirmation_id)
                .map_err(|_| {
                    self.process.abort();
                    RecoveryDenyReason::NativeFailure
                })?;
            if parsed.grant_id != grant.grant_id
                || parsed.confirmation_id != grant.confirmation_id
                || parsed.action != grant.action
                || parsed.issued_at_unix_ms != grant.issued_at_unix_ms
                || parsed.expires_at_unix_ms != grant.expires_at_unix_ms
                || parsed.single_use != grant.single_use
            {
                self.process.abort();
                return Err(RecoveryDenyReason::NativeFailure);
            }
            Ok(())
        }
    }

    fn h5_host_fixture_executable(repo_root: &Path) -> Result<PathBuf, String> {
        let executable = repo_root
            .join("src-tauri")
            .join("target")
            .join("debug")
            .join(if cfg!(windows) {
                "d29h5-authority-fixture.exe"
            } else {
                "d29h5-authority-fixture"
            });
        if executable.is_file() {
            return Ok(executable);
        }
        let status = Command::new("cargo")
            .current_dir(repo_root)
            .args(["build", "--quiet", "--locked", "--manifest-path"])
            .arg(repo_root.join("src-tauri").join("Cargo.toml"))
            .args([
                "--bin",
                "d29h5-authority-fixture",
                "--features",
                "d29-h5-host-fixture",
            ])
            .env("CARGO_BUILD_JOBS", "1")
            .env("CARGO_INCREMENTAL", "0")
            .env("CARGO_TERM_COLOR", "never")
            .status()
            .map_err(|error| format!("build persistent H5 Host fixture: {error}"))?;
        if !status.success() || !executable.is_file() {
            return Err("persistent H5 Host fixture executable was not produced".to_string());
        }
        Ok(executable)
    }

    fn parse_h5_response(body: Vec<u8>, _operation: &str) -> Result<H5HostResponse, String> {
        serde_json::from_slice(&body).map_err(|_| "H5 Host response JSON malformed".to_string())
    }

    fn parse_h5_grant(
        grant: H5GrantWire,
        request: &RecoveryActionRequest,
        expected_used: bool,
        expected_confirmation_id: &str,
    ) -> Result<RecoveryGrantEvidence, String> {
        if !valid_h5_id(&grant.grant_id)
            || grant.confirmation_id != expected_confirmation_id
            || grant.binding != h5_wire_binding(request)
            || grant.issued_at_unix_ms >= grant.expires_at_unix_ms
            || !grant.single_use
            || grant.used != expected_used
        {
            return Err("H5 Host recovery grant binding was invalid".to_string());
        }
        Ok(RecoveryGrantEvidence {
            grant_id: grant.grant_id,
            confirmation_id: grant.confirmation_id,
            action: request.clone(),
            issued_at_unix_ms: grant.issued_at_unix_ms,
            expires_at_unix_ms: grant.expires_at_unix_ms,
            single_use: grant.single_use,
            used: grant.used,
        })
    }

    fn parse_h5_denied_response(
        response: &H5HostResponse,
        operation: &str,
        require_zero_modifying_syscalls: bool,
    ) -> Result<RecoveryDenyReason, String> {
        if response.operation != operation
            || response.status != "denied"
            || response.recovery_grant.is_some()
            || response.confirmation.is_some()
            || response.confirmation_consumed.is_some()
            || response.trusted_confirmation.is_some()
            || response.request_derived_confirmation.is_some()
            || response.production_registry_size.is_some()
            || response.test_registry_size.is_some()
            || response.same_sqlite_row.is_some()
            || response.authorization_revision.is_some()
            || response.denial.is_none()
            || (require_zero_modifying_syscalls && response.modifying_syscalls != Some(0))
        {
            return Err("H5 Host denial response shape invalid".to_string());
        }
        Ok(match response.denial.as_deref().unwrap() {
            "authorization_disabled_or_scope_denied" | "root_disabled_or_scope_denied" => {
                RecoveryDenyReason::AuthorizationDisabled
            }
            "stale_revision" => RecoveryDenyReason::StaleRevision,
            "confirmation_missing" => RecoveryDenyReason::ConfirmationMissing,
            "confirmation_mismatch" => RecoveryDenyReason::ConfirmationMismatch,
            "confirmation_expired" => RecoveryDenyReason::ConfirmationExpired,
            "recovery_grant_replay_or_missing" | "recovery_grant_revalidation_denied" => {
                RecoveryDenyReason::RecoveryGrantReplay
            }
            _ => RecoveryDenyReason::RecoveryBlocked,
        })
    }

    fn h5_wire_binding(request: &RecoveryActionRequest) -> H5WireBinding {
        H5WireBinding {
            action_id: request.action_id.clone(),
            life_id: request.life_id.clone(),
            task_id: request.task_id.clone(),
            capability_id: request.capability_id.clone(),
            authorization_revision: request.authorization_revision,
            workspace_root_identity: journal_identity_wire(request.workspace_root_identity),
            relative_path: request
                .relative_path
                .as_path()
                .to_string_lossy()
                .into_owned(),
            target_identity: journal_identity_wire(request.target_identity),
            transaction_id: request.transaction_id.as_str().to_string(),
            journal_integrity_hash: request.journal_integrity_hash.clone(),
            current_sha256: request.current_sha256.clone(),
            current_bytes: request.current_bytes as u64,
            restore_sha256: request.restore_sha256.clone(),
            restore_bytes: request.restore_bytes as u64,
            original_replacement_sha256: request.original_replacement_sha256.clone(),
        }
    }

    fn valid_h5_id(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= H5_MAX_ID_CHARS
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-.\\".contains(&byte))
    }

    fn workspace_identity_wire(identity: WorkspaceRootIdentity) -> String {
        let volume = identity.volume_serial_number().unwrap_or_default();
        let file_id = identity
            .file_id()
            .map(|bytes| {
                bytes
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .unwrap_or_else(|| "none".to_string());
        format!("v{volume:x}f{file_id}")
    }

    fn journal_identity_wire(identity: RecoveryJournalIdentity) -> String {
        let file_id = identity
            .file_id()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        format!("v{:x}f{file_id}", identity.volume_serial_number())
    }

    fn allow_fence() -> impl WorkspaceReplaceCommitFence {
        || Ok(())
    }

    fn run_started_marker_fault(
        fixture: &Fixture,
        fault: RecoveryMarkerPersistenceTestFault,
    ) -> H5ReplaceExecutionResult {
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        execute_h5b_replace_after_host_pass_with_started_marker_fault(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(BEFORE),
            REPLACEMENT,
            &cancellation,
            &mut fence,
            fault,
        )
        .expect("Started marker fault execution")
    }

    fn recovery_entry_count(fixture: &Fixture) -> usize {
        fs::read_dir(fixture.store.recovery_root())
            .expect("recovery namespace enumeration")
            .count()
    }

    struct RevokeAtFenceAuthority {
        inner: Arc<TestRecoveryAuthority>,
    }

    impl RecoveryAuthorityPort for RevokeAtFenceAuthority {
        fn issue_recovery_grant(
            &self,
            request: &RecoveryActionRequest,
        ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason> {
            self.inner.issue_recovery_grant(request)
        }

        fn revalidate_recovery_grant(
            &self,
            grant: &RecoveryGrantEvidence,
            request: &RecoveryActionRequest,
        ) -> Result<(), RecoveryDenyReason> {
            self.inner.disable_test_authorization();
            self.inner.revalidate_recovery_grant(grant, request)
        }
    }

    struct ChangeAfterIssueAuthority {
        inner: Arc<TestRecoveryAuthority>,
        target: PathBuf,
    }

    impl RecoveryAuthorityPort for ChangeAfterIssueAuthority {
        fn issue_recovery_grant(
            &self,
            request: &RecoveryActionRequest,
        ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason> {
            let grant = self.inner.issue_recovery_grant(request)?;
            fs::write(&self.target, b"diverged after recovery grant")
                .expect("change current bytes after recovery grant");
            Ok(grant)
        }

        fn revalidate_recovery_grant(
            &self,
            grant: &RecoveryGrantEvidence,
            request: &RecoveryActionRequest,
        ) -> Result<(), RecoveryDenyReason> {
            self.inner.revalidate_recovery_grant(grant, request)
        }
    }

    struct RebindAfterIssueAuthority {
        inner: Arc<TestRecoveryAuthority>,
        target: PathBuf,
        moved: PathBuf,
    }

    impl RecoveryAuthorityPort for RebindAfterIssueAuthority {
        fn issue_recovery_grant(
            &self,
            request: &RecoveryActionRequest,
        ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason> {
            let grant = self.inner.issue_recovery_grant(request)?;
            fs::rename(&self.target, &self.moved).expect("rename target after recovery grant");
            fs::write(&self.target, b"new target identity")
                .expect("create replacement target after recovery grant");
            Ok(grant)
        }

        fn revalidate_recovery_grant(
            &self,
            grant: &RecoveryGrantEvidence,
            request: &RecoveryActionRequest,
        ) -> Result<(), RecoveryDenyReason> {
            self.inner.revalidate_recovery_grant(grant, request)
        }
    }

    struct CancelAtFenceAuthority {
        inner: Arc<TestRecoveryAuthority>,
    }

    impl RecoveryAuthorityPort for CancelAtFenceAuthority {
        fn issue_recovery_grant(
            &self,
            request: &RecoveryActionRequest,
        ) -> Result<RecoveryGrantEvidence, RecoveryDenyReason> {
            self.inner.issue_recovery_grant(request)
        }

        fn revalidate_recovery_grant(
            &self,
            _grant: &RecoveryGrantEvidence,
            _request: &RecoveryActionRequest,
        ) -> Result<(), RecoveryDenyReason> {
            Err(RecoveryDenyReason::Cancellation)
        }
    }

    struct BusyHandle(windows_sys::Win32::Foundation::HANDLE);

    impl Drop for BusyHandle {
        fn drop(&mut self) {
            unsafe {
                let _ = windows_sys::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }

    fn open_busy_target(path: &Path) -> BusyHandle {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING,
        };

        let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        wide.push(0);
        let handle: HANDLE = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        assert!(!handle.is_null() && handle != INVALID_HANDLE_VALUE);
        BusyHandle(handle)
    }

    fn replacement_recovery_case() -> (
        Fixture,
        RecoveryJournalV1,
        RecoveryActionRequest,
        Arc<TestRecoveryAuthority>,
    ) {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let authority = TestRecoveryAuthority::new(2);
        let action = fixture.action(&journal);
        authority.provision_trusted_confirmation(&action);
        (fixture, journal, action, authority)
    }

    #[test]
    fn marker_roundtrip_is_strict_and_binds_journal_hash() {
        let fixture = Fixture::new();
        let journal = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context())
            .unwrap();
        let marker = RecoveryMarkerV1::new(
            journal.transaction_id().clone(),
            journal.integrity_hash_bytes(),
            RecoveryMarkerState::Started,
        );
        let bytes = marker.to_bytes().unwrap();
        assert_eq!(RecoveryMarkerV1::from_bytes(&bytes).unwrap(), marker);
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(matches!(
            RecoveryMarkerV1::from_bytes(&extra),
            Err(RecoveryJournalError::Corrupt(_))
        ));
        let mut unsupported = bytes.clone();
        unsupported[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert!(matches!(
            RecoveryMarkerV1::from_bytes(&unsupported),
            Err(RecoveryJournalError::UnsupportedVersion(2))
        ));
        assert!(!bytes
            .windows(b"confirmation_id".len())
            .any(|window| window == b"confirmation_id"));
        assert!(!bytes
            .windows(b"grant_id".len())
            .any(|window| window == b"grant_id"));
    }

    #[test]
    fn transaction_scanner_exposes_exact_four_legal_states() {
        let fixture = Fixture::new();
        let prepared = fixture
            .store
            .create_prepared(&fixture.target(), fixture.context())
            .unwrap();
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(
            scan.valid_transactions().next().unwrap().state(),
            RecoveryTransactionState::PreparedOnly
        );
        fixture.store.persist_started(&prepared).unwrap();
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
        fixture.store.persist_committed(&prepared).unwrap();
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            RecoveryTransactionState::CommittedTerminal
        );
    }

    #[test]
    fn started_recovery_uses_fresh_confirmation_and_restores_exact_preimage() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let authority = TestRecoveryAuthority::new(2);
        let action = fixture.action(&journal);
        authority.provision_trusted_confirmation(&action);
        let executor = H5RecoveryExecutor::new(
            RecoveryJournalStore::from_runtime_profile(&fixture.profile).unwrap(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(result.outcome, RecoveryExecutionOutcome::Recovered);
        assert_eq!(result.mutation_count, 1);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
        let state = executor
            .scan()
            .unwrap()
            .valid_transactions()
            .next()
            .unwrap()
            .state();
        assert_eq!(state, RecoveryTransactionState::RecoveredTerminal);
        assert_eq!(authority.provenance(), (1, 0));
    }

    #[test]
    fn recovery_observes_invalid_utf8_as_bounded_raw_bytes() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        let invalid_current = [0xff, 0x00, 0xfe, 0x80];
        fs::write(
            fixture.workspace_dir.path().join("target.txt"),
            invalid_current,
        )
        .unwrap();
        let authority = TestRecoveryAuthority::new(2);
        let action = fixture.action(&journal);
        authority.provision_trusted_confirmation(&action);
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(result.outcome, RecoveryExecutionOutcome::Recovered);
        assert_eq!(result.mutation_count, 1);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn replacement_bytes_without_commit_marker_still_require_fresh_confirmation() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            TestRecoveryAuthority::new(2) as Arc<dyn RecoveryAuthorityPort>,
        );
        let action = fixture.action(&journal);
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::ConfirmationMissing)
        );
        assert_eq!(result.mutation_count, 0);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
    }

    #[test]
    fn current_preimage_is_recovered_noop_without_workspace_write() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        let authority = TestRecoveryAuthority::new(2);
        let action = fixture.action(&journal);
        authority.provision_trusted_confirmation(&action);
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(result.outcome, RecoveryExecutionOutcome::RecoveredNoOp);
        assert_eq!(result.mutation_count, 0);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn h5_committed_requires_durable_commit_marker() {
        let fixture = Fixture::new();
        let store_for_fence = fixture.store.clone();
        let mut fence = move || {
            let snapshot = store_for_fence.scan_transactions().unwrap();
            assert_eq!(
                snapshot.valid_transactions().next().unwrap().state(),
                RecoveryTransactionState::PreparedOnly
            );
            Ok(())
        };
        let cancellation = AtomicBool::new(false);
        let result = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(BEFORE),
            REPLACEMENT,
            &cancellation,
            &mut fence,
        )
        .unwrap();
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Committed
        );
        assert!(matches!(
            result.native_diagnostics,
            WorkspaceReplaceCommitOutcome::Committed { .. }
        ));
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            RecoveryTransactionState::CommittedTerminal
        );
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
    }

    #[test]
    fn h5_preimage_must_equal_expected_sha() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let expected_sha256 = sha256_hex(BEFORE).to_ascii_uppercase();
        let result = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &expected_sha256,
            REPLACEMENT,
            &cancellation,
            &mut fence,
        )
        .unwrap();

        assert_eq!(result.journal.before_sha256(), sha256_hex(BEFORE));
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Committed
        );
        assert!(!fixture
            .store
            .scan_transactions()
            .unwrap()
            .has_ambiguous_target());
    }

    #[test]
    fn preimage_mismatch_creates_no_journal() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(REPLACEMENT.as_bytes()),
            REPLACEMENT,
            &cancellation,
            &mut fence,
        );

        assert!(matches!(
            result,
            Err(RecoveryJournalError::PreimageConflict)
        ));
        assert_eq!(recovery_entry_count(&fixture), 0);
    }

    #[test]
    fn preimage_mismatch_creates_no_started_marker() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(REPLACEMENT.as_bytes()),
            REPLACEMENT,
            &cancellation,
            &mut fence,
        );

        assert!(matches!(
            result,
            Err(RecoveryJournalError::PreimageConflict)
        ));
        assert_eq!(recovery_entry_count(&fixture), 0);
        assert!(!fixture
            .store
            .recovery_root()
            .join("h5-preimage-mismatch.started")
            .exists());
    }

    #[test]
    fn preimage_mismatch_mutates_workspace_zero() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(REPLACEMENT.as_bytes()),
            REPLACEMENT,
            &cancellation,
            &mut fence,
        );

        assert!(matches!(
            result,
            Err(RecoveryJournalError::PreimageConflict)
        ));
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn preimage_mismatch_does_not_create_ambiguous_pending_transaction() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(REPLACEMENT.as_bytes()),
            REPLACEMENT,
            &cancellation,
            &mut fence,
        );

        assert!(matches!(
            result,
            Err(RecoveryJournalError::PreimageConflict)
        ));
        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.valid_transactions().count(), 0);
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
    }

    #[test]
    fn clean_retry_after_preimage_mismatch_can_create_one_transaction() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut first_fence = allow_fence();
        let first = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(REPLACEMENT.as_bytes()),
            REPLACEMENT,
            &cancellation,
            &mut first_fence,
        );
        assert!(matches!(first, Err(RecoveryJournalError::PreimageConflict)));
        assert_eq!(recovery_entry_count(&fixture), 0);

        fs::write(
            fixture.workspace_dir.path().join("target.txt"),
            REPLACEMENT.as_bytes(),
        )
        .unwrap();
        let mut second_fence = allow_fence();
        let second = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(REPLACEMENT.as_bytes()),
            REPLACEMENT,
            &cancellation,
            &mut second_fence,
        )
        .unwrap();

        assert_eq!(
            second.transaction_outcome,
            H5ReplaceTransactionOutcome::Committed
        );
        assert_eq!(recovery_entry_count(&fixture), 3);
        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.valid_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions()
                .next()
                .unwrap()
                .journal()
                .before_sha256(),
            sha256_hex(REPLACEMENT.as_bytes())
        );
    }

    #[test]
    fn started_transaction_before_hash_equals_h4_expected() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let expected_sha256 = sha256_hex(BEFORE).to_ascii_uppercase();
        let result = execute_h5b_replace_after_host_pass_with_test_fault(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &expected_sha256,
            REPLACEMENT,
            &cancellation,
            &mut fence,
            WorkspaceReplaceTestFault::AfterCommitFenceBeforePostFenceChecks,
        )
        .unwrap();

        assert_eq!(result.journal.before_sha256(), sha256_hex(BEFORE));
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::Required,
            }
        );
        assert!(matches!(
            &result.native_diagnostics,
            WorkspaceReplaceCommitOutcome::Denied { evidence, .. }
                if evidence.before_sha256.as_deref() == Some(sha256_hex(BEFORE).as_str())
        ));
    }

    #[test]
    fn commit_unknown_recovery_preimage_equals_h4_expected() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let expected_sha256 = sha256_hex(BEFORE).to_ascii_uppercase();
        let result = execute_h5b_replace_after_host_pass_with_test_fault(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &expected_sha256,
            REPLACEMENT,
            &cancellation,
            &mut fence,
            WorkspaceReplaceTestFault::AfterFirstWrite,
        )
        .unwrap();

        assert_eq!(result.journal.before_sha256(), sha256_hex(BEFORE));
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::CommitUnknown {
                recovery_required: true,
            }
        );
        assert!(matches!(
            result.native_diagnostics,
            WorkspaceReplaceCommitOutcome::CommitUnknown { .. }
        ));
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .journal()
                .before_sha256(),
            sha256_hex(BEFORE)
        );
    }

    #[test]
    fn invalid_expected_sha_creates_no_journal() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            "not-a-sha256",
            REPLACEMENT,
            &cancellation,
            &mut fence,
        );

        assert!(matches!(
            result,
            Err(RecoveryJournalError::InvalidField {
                field: "expected_sha256",
                ..
            })
        ));
        assert_eq!(recovery_entry_count(&fixture), 0);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn r2_started_persistence_reconciliation_still_passes() {
        for fault in [
            RecoveryMarkerPersistenceTestFault::CreateBeforeArtifact,
            RecoveryMarkerPersistenceTestFault::FlushAfterCreate,
            RecoveryMarkerPersistenceTestFault::ReopenAfterCreate,
            RecoveryMarkerPersistenceTestFault::CorruptAfterCreate,
        ] {
            let fixture = Fixture::new();
            let result = run_started_marker_fault(&fixture, fault);
            let scan = fixture.store.scan_transactions().unwrap();
            match fault {
                RecoveryMarkerPersistenceTestFault::CreateBeforeArtifact => {
                    assert_eq!(
                        result.transaction_outcome,
                        H5ReplaceTransactionOutcome::Denied {
                            recovery: H5RecoveryDisposition::None,
                        }
                    );
                    assert_eq!(
                        scan.valid_transactions().next().unwrap().state(),
                        RecoveryTransactionState::PreparedOnly
                    );
                }
                RecoveryMarkerPersistenceTestFault::FlushAfterCreate
                | RecoveryMarkerPersistenceTestFault::ReopenAfterCreate => {
                    assert_eq!(
                        result.transaction_outcome,
                        H5ReplaceTransactionOutcome::Denied {
                            recovery: H5RecoveryDisposition::Required,
                        }
                    );
                    assert_eq!(
                        scan.valid_transactions().next().unwrap().state(),
                        RecoveryTransactionState::RecoveryRequired
                    );
                }
                RecoveryMarkerPersistenceTestFault::CorruptAfterCreate => {
                    assert_eq!(
                        result.transaction_outcome,
                        H5ReplaceTransactionOutcome::LifecycleUnknown {
                            workspace_mutation_started: false,
                        }
                    );
                    assert_eq!(scan.valid_transactions().count(), 0);
                    assert_eq!(scan.actionable_recovery_transactions().count(), 0);
                }
            }
        }
    }

    #[test]
    fn commit_marker_failure_is_unknown_and_never_retries_replace() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass_internal(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(BEFORE),
            REPLACEMENT,
            &cancellation,
            &mut fence,
            true,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::CommitUnknown {
                recovery_required: true
            }
        );
        assert!(matches!(
            result.native_diagnostics,
            WorkspaceReplaceCommitOutcome::Committed { .. }
        ));
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
    }

    #[test]
    fn native_commit_unknown_maps_to_h5_commit_unknown_without_retry() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass_with_test_fault(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(BEFORE),
            REPLACEMENT,
            &cancellation,
            &mut fence,
            WorkspaceReplaceTestFault::AfterFirstWrite,
        )
        .unwrap();
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::CommitUnknown {
                recovery_required: true
            }
        );
        assert!(matches!(
            &result.native_diagnostics,
            WorkspaceReplaceCommitOutcome::CommitUnknown { .. }
        ));
        if let WorkspaceReplaceCommitOutcome::CommitUnknown { evidence, .. } =
            &result.native_diagnostics
        {
            assert_eq!(evidence.automatic_retries, 0);
        } else {
            panic!("expected native CommitUnknown diagnostics");
        }
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
    }

    #[test]
    fn started_then_native_denied_reports_recovery_required() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass_with_test_fault(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(BEFORE),
            REPLACEMENT,
            &cancellation,
            &mut fence,
            WorkspaceReplaceTestFault::AfterCommitFenceBeforePostFenceChecks,
        )
        .unwrap();
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::Required
            }
        );
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn started_then_native_conflict_reports_recovery_required() {
        let fixture = Fixture::new();
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let result = execute_h5b_replace_after_host_pass_with_test_fault(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(BEFORE),
            REPLACEMENT,
            &cancellation,
            &mut fence,
            WorkspaceReplaceTestFault::PostFenceHashMismatch,
        )
        .unwrap();
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Conflict {
                recovery: H5RecoveryDisposition::Required
            }
        );
        assert_eq!(
            fixture
                .store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveryRequired
        );
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn started_create_failure_with_no_artifact_is_prepared_only() {
        let fixture = Fixture::new();
        let result = run_started_marker_fault(
            &fixture,
            RecoveryMarkerPersistenceTestFault::CreateBeforeArtifact,
        );

        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::None,
            }
        );
        assert!(matches!(
            &result.native_diagnostics,
            WorkspaceReplaceCommitOutcome::Denied { evidence, .. }
                if evidence.modifying_syscalls == 0
        ));
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(scan.valid_transactions().count(), 1);
        assert_eq!(
            scan.valid_transactions().next().unwrap().state(),
            RecoveryTransactionState::PreparedOnly
        );
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn started_reopen_failure_with_valid_marker_is_not_reported_no_recovery() {
        let fixture = Fixture::new();
        let result = run_started_marker_fault(
            &fixture,
            RecoveryMarkerPersistenceTestFault::ReopenAfterCreate,
        );

        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::Required,
            }
        );
        assert!(matches!(
            &result.native_diagnostics,
            WorkspaceReplaceCommitOutcome::Denied { evidence, .. }
                if evidence.modifying_syscalls == 0
        ));
        let scan = fixture.store.scan_transactions().unwrap();
        let snapshot = scan.valid_transactions().next().unwrap();
        assert_eq!(snapshot.state(), RecoveryTransactionState::RecoveryRequired);
        assert!(snapshot.started().is_some());
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn started_flush_failure_reconciles_durable_lifecycle() {
        let fixture = Fixture::new();
        let result = run_started_marker_fault(
            &fixture,
            RecoveryMarkerPersistenceTestFault::FlushAfterCreate,
        );

        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::Required,
            }
        );
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(
            scan.valid_transactions().next().unwrap().state(),
            RecoveryTransactionState::RecoveryRequired
        );
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn corrupt_started_after_persistence_failure_is_lifecycle_unknown() {
        let fixture = Fixture::new();
        let result = run_started_marker_fault(
            &fixture,
            RecoveryMarkerPersistenceTestFault::CorruptAfterCreate,
        );

        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::LifecycleUnknown {
                workspace_mutation_started: false,
            }
        );
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(scan.valid_transactions().count(), 0);
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
        assert!(scan
            .items()
            .iter()
            .any(|item| matches!(item, RecoveryTransactionScanItem::CorruptArtifact { .. })));
        assert!(fixture
            .store
            .recovery_root()
            .join(format!(
                "{}.started",
                result.journal.transaction_id().as_str()
            ))
            .is_file());
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn started_failure_never_allows_workspace_mutation() {
        for fault in [
            RecoveryMarkerPersistenceTestFault::CreateBeforeArtifact,
            RecoveryMarkerPersistenceTestFault::FlushAfterCreate,
            RecoveryMarkerPersistenceTestFault::ReopenAfterCreate,
            RecoveryMarkerPersistenceTestFault::CorruptAfterCreate,
        ] {
            let fixture = Fixture::new();
            let result = run_started_marker_fault(&fixture, fault);
            assert!(matches!(
                &result.native_diagnostics,
                WorkspaceReplaceCommitOutcome::Denied { evidence, .. }
                    if evidence.modifying_syscalls == 0
                        && !evidence.mutation_started
            ));
            assert_eq!(
                fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
                BEFORE,
                "Started persistence fault {fault:?} mutated the workspace"
            );
        }
    }

    #[test]
    fn started_failure_never_retries_replace() {
        let fixture = Fixture::new();
        let fence_calls = Arc::new(AtomicUsize::new(0));
        let fence_calls_for_fence = Arc::clone(&fence_calls);
        let mut fence = move || {
            fence_calls_for_fence.fetch_add(1, Ordering::SeqCst);
            Ok(())
        };
        let cancellation = AtomicBool::new(false);
        let result = execute_h5b_replace_after_host_pass_with_started_marker_fault(
            &fixture.store,
            &fixture.root,
            fixture.target(),
            fixture.context(),
            &sha256_hex(BEFORE),
            REPLACEMENT,
            &cancellation,
            &mut fence,
            RecoveryMarkerPersistenceTestFault::ReopenAfterCreate,
        )
        .unwrap();

        assert_eq!(fence_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::Required,
            }
        );
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(scan.valid_transactions().count(), 1);
        assert_eq!(scan.actionable_recovery_transactions().count(), 1);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
    }

    #[test]
    fn started_failure_result_matches_fresh_transaction_scan() {
        for (fault, expected_state, expected_outcome) in [
            (
                RecoveryMarkerPersistenceTestFault::CreateBeforeArtifact,
                Some(RecoveryTransactionState::PreparedOnly),
                H5RecoveryDisposition::None,
            ),
            (
                RecoveryMarkerPersistenceTestFault::FlushAfterCreate,
                Some(RecoveryTransactionState::RecoveryRequired),
                H5RecoveryDisposition::Required,
            ),
            (
                RecoveryMarkerPersistenceTestFault::ReopenAfterCreate,
                Some(RecoveryTransactionState::RecoveryRequired),
                H5RecoveryDisposition::Required,
            ),
        ] {
            let fixture = Fixture::new();
            let result = run_started_marker_fault(&fixture, fault);
            let scan = fixture.store.scan_transactions().unwrap();
            assert_eq!(
                scan.valid_transactions()
                    .next()
                    .map(|snapshot| snapshot.state()),
                expected_state,
                "fresh scan disagreed for Started fault {fault:?}"
            );
            assert_eq!(
                result.transaction_outcome,
                H5ReplaceTransactionOutcome::Denied {
                    recovery: expected_outcome,
                },
                "H5 result disagreed with fresh scan for Started fault {fault:?}"
            );
        }

        let fixture = Fixture::new();
        let result = run_started_marker_fault(
            &fixture,
            RecoveryMarkerPersistenceTestFault::CorruptAfterCreate,
        );
        let scan = fixture.store.scan_transactions().unwrap();
        assert_eq!(scan.valid_transactions().count(), 0);
        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::LifecycleUnknown {
                workspace_mutation_started: false,
            }
        );
    }

    #[test]
    fn lifecycle_unknown_is_not_committed() {
        let fixture = Fixture::new();
        let result = run_started_marker_fault(
            &fixture,
            RecoveryMarkerPersistenceTestFault::CorruptAfterCreate,
        );

        assert!(!matches!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Committed
        ));
        assert!(!fixture
            .store
            .recovery_root()
            .join(format!(
                "{}.committed",
                result.journal.transaction_id().as_str()
            ))
            .exists());
    }

    #[test]
    fn lifecycle_unknown_does_not_issue_recovery_grant() {
        let fixture = Fixture::new();
        let result = run_started_marker_fault(
            &fixture,
            RecoveryMarkerPersistenceTestFault::CorruptAfterCreate,
        );
        let journal = &result.journal;
        let action = RecoveryActionRequest {
            action_id: "lifecycle-unknown-action".to_string(),
            life_id: journal.life_id().to_string(),
            task_id: journal.task_id().to_string(),
            capability_id: H5_RECOVER_REPLACE_CAPABILITY_ID.to_string(),
            workspace_root_identity: journal.workspace_root_identity(),
            relative_path: journal.relative_path().clone(),
            target_identity: journal.target_identity(),
            transaction_id: journal.transaction_id().clone(),
            journal_integrity_hash: journal.integrity_hash(),
            current_sha256: sha256_hex(BEFORE),
            current_bytes: BEFORE.len(),
            restore_sha256: journal.before_sha256(),
            restore_bytes: journal.before_bytes(),
            original_replacement_sha256: journal.replacement_sha256(),
            authorization_revision: 2,
        };
        let authority = TestRecoveryAuthority::new(2);
        authority.provision_trusted_confirmation(&action);
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let recovery = executor.recover(action);

        assert_eq!(
            recovery.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::RecoveryBlocked)
        );
        assert!(!recovery.grant_issued);
        assert_eq!(authority.grant_count(), 0);
        assert_eq!(recovery.mutation_count, 0);
    }

    #[test]
    fn valid_started_after_local_error_remains_recovery_required() {
        let fixture = Fixture::new();
        let result = run_started_marker_fault(
            &fixture,
            RecoveryMarkerPersistenceTestFault::ReopenAfterCreate,
        );

        assert_eq!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::Required,
            }
        );
        assert!(!matches!(
            result.transaction_outcome,
            H5ReplaceTransactionOutcome::Denied {
                recovery: H5RecoveryDisposition::None
            }
        ));
    }

    #[test]
    fn disabled_test_authority_denies_after_grant_before_restore() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let authority = TestRecoveryAuthority::new(2);
        let action = fixture.action(&journal);
        authority.provision_trusted_confirmation(&action);
        authority.disable_test_authorization();
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::AuthorizationDisabled)
        );
        assert_eq!(result.mutation_count, 0);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
    }

    #[test]
    fn process_host_recovery_requires_independent_confirmation() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let authority = ProcessIsolatedH5RecoveryAuthority::new(
            fixture.root.identity(),
            journal.life_id(),
            journal.task_id(),
        )
        .unwrap();
        let action = fixture.action(&journal);
        assert_eq!(
            authority.issue_recovery_grant(&action),
            Err(RecoveryDenyReason::ConfirmationMissing)
        );
        assert_eq!(authority.provenance(), (0, 0));
        authority.provision_trusted_confirmation(&action).unwrap();
        let _grant = authority.issue_recovery_grant(&action).unwrap();
        assert_eq!(authority.provenance(), (1, 0));
        assert!(authority.shutdown());
    }

    #[test]
    fn process_host_successful_recovery_uses_real_sqlite_d28() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let authority = ProcessIsolatedH5RecoveryAuthority::new(
            fixture.root.identity(),
            journal.life_id(),
            journal.task_id(),
        )
        .unwrap();
        let action = fixture.action(&journal);
        authority.provision_trusted_confirmation(&action).unwrap();
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(result.outcome, RecoveryExecutionOutcome::Recovered);
        assert_eq!(result.mutation_count, 1);
        assert_eq!(result.grant_issued, true);
        assert_eq!(result.marker_persisted, true);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            BEFORE
        );
        assert_eq!(authority.provenance(), (1, 0));
        assert!(authority.shutdown());
    }

    #[test]
    fn process_host_rev2_to_rev3_at_native_recovery_fence_mutates_zero() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let authority = ProcessIsolatedH5RecoveryAuthority::new(
            fixture.root.identity(),
            journal.life_id(),
            journal.task_id(),
        )
        .unwrap();
        let action = fixture.action(&journal);
        authority.provision_trusted_confirmation(&action).unwrap();
        authority.arm_disable_at_next_revalidation();
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::AuthorizationDisabled)
        );
        assert_eq!(result.grant_issued, true);
        assert_eq!(result.mutation_count, 0);
        assert_eq!(authority.sqlite_disable_count(), 1);
        assert_eq!(authority.provenance(), (1, 0));
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
        assert!(authority.shutdown());
    }

    #[test]
    fn corrupt_lifecycle_never_issues_recovery_grant_or_mutates_workspace() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let action = fixture.action(&journal);
        let committed = fixture.store.persist_committed(&journal).unwrap();
        let mut bytes = committed.to_bytes().unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        fs::write(
            fixture
                .store
                .recovery_root()
                .join(format!("{}.committed", committed.transaction_id().as_str())),
            bytes,
        )
        .unwrap();
        let authority = TestRecoveryAuthority::new(2);
        authority.provision_trusted_confirmation(&action);
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::RecoveryBlocked)
        );
        assert_eq!(result.grant_issued, false);
        assert_eq!(result.mutation_count, 0);
        assert_eq!(authority.grant_count(), 0);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
    }

    #[test]
    fn wrong_workspace_root_cannot_issue_recovery_grant() {
        let fixture = Fixture::new();
        let other = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let mut action = fixture.action(&journal);
        action.workspace_root_identity =
            RecoveryJournalIdentity::from_workspace_identity(other.root.identity()).unwrap();
        let authority = TestRecoveryAuthority::new(2);
        authority.provision_trusted_confirmation(&action);
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::RecoveryBlocked)
        );
        assert_eq!(result.mutation_count, 0);
        assert!(!result.grant_issued);
        assert_eq!(authority.grant_count(), 0);
    }

    #[test]
    fn recovery_grant_is_single_use() {
        let (_fixture, journal, action, authority) = replacement_recovery_case();
        let grant = authority
            .issue_recovery_grant(&action)
            .expect("fresh recovery grant");
        authority
            .revalidate_recovery_grant(&grant, &action)
            .expect("first recovery grant use");
        assert_eq!(
            authority.revalidate_recovery_grant(&grant, &action),
            Err(RecoveryDenyReason::RecoveryGrantReplay)
        );
        assert_eq!(grant.action.transaction_id(), journal.transaction_id());
    }

    #[test]
    fn rev2_to_rev3_at_recovery_fence_mutates_zero() {
        let (fixture, _journal, action, authority) = replacement_recovery_case();
        let revoking = Arc::new(RevokeAtFenceAuthority {
            inner: Arc::clone(&authority),
        });
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            revoking as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::AuthorizationDisabled)
        );
        assert_eq!(result.mutation_count, 0);
        assert!(result.grant_issued);
        assert_eq!(authority.current_revision(), 3);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
    }

    #[test]
    fn current_hash_change_after_grant_is_recovery_conflict() {
        let (fixture, _journal, action, authority) = replacement_recovery_case();
        let target = fixture.workspace_dir.path().join("target.txt");
        let changing = Arc::new(ChangeAfterIssueAuthority {
            inner: Arc::clone(&authority),
            target: target.clone(),
        });
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            changing as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(result.outcome, RecoveryExecutionOutcome::RecoveryConflict);
        assert_eq!(result.mutation_count, 0);
        assert!(result.grant_issued);
        assert_eq!(fs::read(target).unwrap(), b"diverged after recovery grant");
    }

    #[test]
    fn target_identity_change_after_grant_is_denied_without_mutation() {
        let (fixture, _journal, action, authority) = replacement_recovery_case();
        let target = fixture.workspace_dir.path().join("target.txt");
        let moved = fixture.workspace_dir.path().join("target-moved.txt");
        let rebinding = Arc::new(RebindAfterIssueAuthority {
            inner: Arc::clone(&authority),
            target: target.clone(),
            moved: moved.clone(),
        });
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            rebinding as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::TargetIdentityChanged)
        );
        assert_eq!(result.mutation_count, 0);
        assert!(result.grant_issued);
        assert_eq!(fs::read(moved).unwrap(), REPLACEMENT.as_bytes());
        assert_eq!(fs::read(target).unwrap(), b"new target identity");
    }

    #[test]
    fn hard_link_recovery_mutates_zero() {
        let (fixture, _journal, action, authority) = replacement_recovery_case();
        let alias = fixture.workspace_dir.path().join("target-alias.txt");
        fs::hard_link(fixture.workspace_dir.path().join("target.txt"), &alias).unwrap();
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::HardLinkAmbiguous)
        );
        assert_eq!(result.mutation_count, 0);
        assert!(result.grant_issued);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
        assert_eq!(fs::read(alias).unwrap(), REPLACEMENT.as_bytes());
    }

    #[test]
    fn missing_target_is_not_recreated() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let action = fixture.action(&journal);
        let target = fixture.workspace_dir.path().join("target.txt");
        fs::remove_file(&target).unwrap();
        let authority = TestRecoveryAuthority::new(2);
        authority.provision_trusted_confirmation(&action);
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::TargetMissing)
        );
        assert_eq!(result.mutation_count, 0);
        assert!(!result.grant_issued);
        assert!(!target.exists());
    }

    #[test]
    fn reparse_target_recovery_mutates_zero() {
        use std::os::windows::fs::symlink_file;

        let (fixture, _journal, action, authority) = replacement_recovery_case();
        let target = fixture.workspace_dir.path().join("target.txt");
        let moved = fixture.workspace_dir.path().join("target-moved.txt");
        let outside = tempdir().unwrap();
        let outside_file = outside.path().join("outside.txt");
        fs::write(&outside_file, b"outside").unwrap();
        fs::rename(&target, &moved).unwrap();
        symlink_file(&outside_file, &target).unwrap();
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(result.mutation_count, 0);
        assert!(!result.grant_issued);
        assert!(matches!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(_)
        ));
        assert_eq!(fs::read(&outside_file).unwrap(), b"outside");
        assert_eq!(fs::read(&moved).unwrap(), REPLACEMENT.as_bytes());
    }

    #[test]
    fn cancellation_before_and_at_recovery_fence_mutates_zero() {
        let (fixture, _journal, action, authority) = replacement_recovery_case();
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        executor.cancel();
        let result = executor.recover(action.clone());
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::Cancellation)
        );
        assert_eq!(result.mutation_count, 0);
        assert!(!result.grant_issued);

        let (fixture, _journal, action, authority) = replacement_recovery_case();
        let cancelling = Arc::new(CancelAtFenceAuthority {
            inner: Arc::clone(&authority),
        });
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            cancelling as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::Cancellation)
        );
        assert_eq!(result.mutation_count, 0);
        assert!(result.grant_issued);
        assert_eq!(
            fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
            REPLACEMENT.as_bytes()
        );
    }

    #[test]
    fn busy_recovery_target_mutates_zero() {
        let (fixture, _journal, action, _authority) = replacement_recovery_case();
        let target_path = fixture.workspace_dir.path().join("target.txt");
        let target_for_setup = target_path.clone();
        let busy = Arc::new(Mutex::new(None::<BusyHandle>));
        let busy_for_setup = Arc::clone(&busy);
        let setup = move || {
            *busy_for_setup.lock().unwrap() = Some(open_busy_target(&target_for_setup));
        };
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let outcome = fixture
            .root
            .prepare_target(Path::new("target.txt"))
            .unwrap()
            .recover_existing_file_raw_bounded_with_test_setup(
                &action.current_sha256,
                action.current_bytes,
                BEFORE,
                &mut fence,
                &cancellation,
                &setup,
            );
        assert!(matches!(
            outcome,
            WorkspaceRecoveryCommitOutcome::Denied {
                error: WorkspaceReplaceError::TargetBusy,
                ..
            }
        ));
        drop(setup);
        drop(busy);
        assert_eq!(fs::read(&target_path).unwrap(), REPLACEMENT.as_bytes());
    }

    #[test]
    fn committed_and_recovered_markers_are_terminal_for_recovery() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        fixture.store.persist_committed(&journal).unwrap();
        let action = fixture.action(&journal);
        let authority = TestRecoveryAuthority::new(2);
        authority.provision_trusted_confirmation(&action);
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let result = executor.recover(action);
        assert_eq!(
            result.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::RecoveryStateInvalid)
        );
        assert_eq!(result.mutation_count, 0);
        assert!(!result.grant_issued);
        assert_eq!(authority.grant_count(), 0);

        let (fixture, journal, action, authority) = replacement_recovery_case();
        let executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let first = executor.recover(action.clone());
        assert_eq!(first.outcome, RecoveryExecutionOutcome::Recovered);
        let second_authority = TestRecoveryAuthority::new(2);
        second_authority.provision_trusted_confirmation(&action);
        let second_executor = H5RecoveryExecutor::new(
            fixture.store.clone(),
            fixture.root.clone(),
            Arc::clone(&second_authority) as Arc<dyn RecoveryAuthorityPort>,
        );
        let second = second_executor.recover(action);
        assert_eq!(
            second.outcome,
            RecoveryExecutionOutcome::RecoveryDenied(RecoveryDenyReason::RecoveryStateInvalid)
        );
        assert_eq!(second.mutation_count, 0);
        assert_eq!(second_authority.grant_count(), 0);
        assert_eq!(
            second_executor
                .scan()
                .unwrap()
                .valid_transactions()
                .find(|snapshot| snapshot.journal().transaction_id() == journal.transaction_id())
                .unwrap()
                .state(),
            RecoveryTransactionState::RecoveredTerminal
        );
    }

    #[test]
    fn bounded_raw_recovery_restores_utf8_empty_and_arbitrary_current_bytes() {
        let cases = [
            ("valid-utf8-partial", b"partial utf8 state".to_vec()),
            ("empty-intermediate", Vec::new()),
            (
                "arbitrary-diverged",
                vec![0x00, 0xff, 0x41, 0x80, 0x10, 0x7f],
            ),
        ];
        for (label, current) in cases {
            let fixture = Fixture::new();
            let journal = fixture.prepared_started();
            fs::write(fixture.workspace_dir.path().join("target.txt"), &current).unwrap();
            let authority = TestRecoveryAuthority::new(2);
            let action = fixture.action(&journal);
            authority.provision_trusted_confirmation(&action);
            let executor = H5RecoveryExecutor::new(
                fixture.store.clone(),
                fixture.root.clone(),
                Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
            );
            let result = executor.recover(action);
            assert_eq!(
                result.outcome,
                RecoveryExecutionOutcome::Recovered,
                "{label}"
            );
            assert_eq!(result.mutation_count, 1, "{label}");
            assert_eq!(
                fs::read(fixture.workspace_dir.path().join("target.txt")).unwrap(),
                BEFORE,
                "{label}"
            );
        }
    }

    #[test]
    fn prepared_only_history_does_not_create_h5_recovery_block() {
        let fixture = Fixture::new();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(),
                "h5-ambiguous-a",
            )
            .unwrap();
        fixture
            .store
            .create_prepared_with_transaction_id_for_test(
                &fixture.target(),
                fixture.context(),
                "h5-ambiguous-b",
            )
            .unwrap();
        let scan = fixture.store.scan_transactions().unwrap();
        assert!(!scan.has_ambiguous_target());
        assert_eq!(scan.valid_transactions().count(), 2);
        assert_eq!(scan.actionable_recovery_transactions().count(), 0);
    }

    fn replace_to_replacement(fixture: &Fixture) {
        let cancellation = AtomicBool::new(false);
        let mut fence = allow_fence();
        let outcome = fixture
            .root
            .prepare_target(Path::new("target.txt"))
            .unwrap()
            .replace_existing_file_utf8_bounded_with_cancellation(
                &sha256_hex(BEFORE),
                REPLACEMENT,
                &mut fence,
                &cancellation,
            );
        assert!(matches!(
            outcome,
            WorkspaceReplaceCommitOutcome::Committed { .. }
        ));
    }

    fn crash_child_profile(
        app_data: &Path,
        workspace: &Path,
    ) -> (
        VitaAgentRuntimeProfile,
        RecoveryJournalStore,
        TrustedWorkspaceRoot,
    ) {
        let profile = VitaAgentRuntimeProfile::from_explicit_app_data_root(
            app_data.to_path_buf(),
            workspace.to_path_buf(),
        )
        .unwrap();
        profile.ensure_private_runtime_layout().unwrap();
        let store = RecoveryJournalStore::from_runtime_profile(&profile).unwrap();
        let root = profile.workspace_authority().unwrap().clone();
        (profile, store, root)
    }

    /// A test-only entry point used by the parent harness below.  It is
    /// compiled into the test binary only; no production environment variable
    /// or process entry point can trigger a crash injection.
    #[test]
    fn h5b_crash_child_entrypoint() {
        let Ok(scenario) = std::env::var("D29_H5B_CRASH_SCENARIO") else {
            return;
        };
        let app_data =
            Path::new(&std::env::var("D29_H5B_CRASH_APP_DATA").expect("H5-B child app-data path"))
                .to_path_buf();
        let workspace = Path::new(
            &std::env::var("D29_H5B_CRASH_WORKSPACE").expect("H5-B child workspace path"),
        )
        .to_path_buf();
        fs::create_dir_all(&app_data).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("target.txt"), BEFORE).unwrap();
        let (_profile, store, root) = crash_child_profile(&app_data, &workspace);
        let context = crate::recovery_journal::RecoveryJournalContext::new(
            "life-h5",
            "task-h5",
            H5_ORIGINAL_REPLACE_CAPABILITY_ID,
            &sha256_hex(REPLACEMENT.as_bytes()),
            REPLACEMENT.len(),
            "tool-h5-crash",
            "turn-h5-crash",
        )
        .unwrap();
        let expected_sha256 = sha256_hex(BEFORE);
        let journal = store
            .create_prepared_for_expected_preimage(
                &root.prepare_target(Path::new("target.txt")).unwrap(),
                context,
                &expected_sha256,
            )
            .unwrap();
        assert_eq!(journal.before_sha256(), expected_sha256);
        let scenario: u8 = scenario.parse().expect("H5-B crash scenario number");
        if scenario == 1 {
            std::process::abort();
        }
        store.persist_started(&journal).unwrap();
        if scenario == 2 {
            std::process::abort();
        }

        if matches!(scenario, 3 | 4 | 5 | 6 | 7 | 8) {
            let cancellation = AtomicBool::new(false);
            let mut fence = allow_fence();
            let target = root.prepare_target(Path::new("target.txt")).unwrap();
            if scenario == 3 {
                let _ = target.replace_existing_file_utf8_bounded_with_test_fault(
                    &expected_sha256,
                    REPLACEMENT,
                    &mut fence,
                    &cancellation,
                    WorkspaceReplaceTestFault::AbortAfterFirstMutation,
                );
                std::process::abort();
            }
            let outcome = target.replace_existing_file_utf8_bounded_with_cancellation(
                &expected_sha256,
                REPLACEMENT,
                &mut fence,
                &cancellation,
            );
            assert!(matches!(
                outcome,
                WorkspaceReplaceCommitOutcome::Committed { .. }
            ));
            if scenario == 4 {
                std::process::abort();
            }
            if scenario == 5 {
                store.persist_committed(&journal).unwrap();
                std::process::abort();
            }
        }

        if matches!(scenario, 6 | 7 | 8) {
            let snapshot = store
                .scan_transactions()
                .unwrap()
                .valid_transactions()
                .next()
                .cloned()
                .unwrap();
            let current = fs::read(workspace.join("target.txt")).unwrap();
            let action = RecoveryActionRequest::from_snapshot(
                &snapshot,
                &current,
                &format!("crash-recovery-action-{scenario}"),
                2,
            );
            let authority = TestRecoveryAuthority::new(2);
            authority.provision_trusted_confirmation(&action);
            let executor = H5RecoveryExecutor::new(
                store.clone(),
                root.clone(),
                Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
            );
            if scenario == 6 {
                let _ = executor.recover_with_test_fault(
                    action,
                    WorkspaceRecoveryTestFault::AbortAfterFirstMutation,
                );
                std::process::abort();
            }
            if scenario == 7 {
                let result = executor.recover_without_recovered_marker_for_test(action);
                assert_eq!(result.outcome, RecoveryExecutionOutcome::Recovered);
                std::process::abort();
            }
            let result = executor.recover(action);
            assert_eq!(result.outcome, RecoveryExecutionOutcome::Recovered);
            std::process::abort();
        }
        std::process::abort();
    }

    fn run_crash_case(scenario: u8) {
        let app_data = tempdir().expect("H5-B crash app-data temp root");
        let workspace = tempdir().expect("H5-B crash workspace temp root");
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "d29h5::tests::h5b_crash_child_entrypoint",
                "--nocapture",
            ])
            .env("D29_H5B_CRASH_SCENARIO", scenario.to_string())
            .env("D29_H5B_CRASH_APP_DATA", app_data.path())
            .env("D29_H5B_CRASH_WORKSPACE", workspace.path())
            .status()
            .expect("spawn H5-B crash child");
        assert!(
            !status.success(),
            "scenario {scenario} must terminate by abort"
        );

        let (profile, store, root) = crash_child_profile(app_data.path(), workspace.path());
        let current_path = workspace.path().join("target.txt");
        let current = fs::read(&current_path).unwrap();
        let snapshot = store
            .scan_transactions()
            .unwrap()
            .valid_transactions()
            .next()
            .cloned()
            .expect("one valid crash transaction");
        assert_eq!(snapshot.journal().before_sha256(), sha256_hex(BEFORE));
        match scenario {
            1 => {
                assert_eq!(snapshot.state(), RecoveryTransactionState::PreparedOnly);
                assert_eq!(current, BEFORE);
            }
            2 => {
                assert_eq!(snapshot.state(), RecoveryTransactionState::RecoveryRequired);
                assert_eq!(current, BEFORE);
                let authority = TestRecoveryAuthority::new(2);
                let action = RecoveryActionRequest::from_snapshot(
                    &snapshot,
                    &current,
                    "parent-recovery-2",
                    2,
                );
                authority.provision_trusted_confirmation(&action);
                let executor = H5RecoveryExecutor::new(
                    store.clone(),
                    root,
                    Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
                );
                let result = executor.recover(action);
                assert_eq!(result.outcome, RecoveryExecutionOutcome::RecoveredNoOp);
                assert_eq!(result.mutation_count, 0);
                assert_eq!(fs::read(&current_path).unwrap(), BEFORE);
                assert_eq!(
                    store
                        .scan_transactions()
                        .unwrap()
                        .valid_transactions()
                        .next()
                        .unwrap()
                        .state(),
                    RecoveryTransactionState::RecoveredTerminal
                );
            }
            3 | 4 | 6 | 7 => {
                assert_eq!(snapshot.state(), RecoveryTransactionState::RecoveryRequired);
                let action = RecoveryActionRequest::from_snapshot(
                    &snapshot,
                    &current,
                    &format!("parent-recovery-{scenario}"),
                    2,
                );
                let result = if scenario == 3 {
                    let authority = ProcessIsolatedH5RecoveryAuthority::new(
                        root.identity(),
                        snapshot.journal().life_id(),
                        snapshot.journal().task_id(),
                    )
                    .unwrap();
                    authority.provision_trusted_confirmation(&action).unwrap();
                    let executor = H5RecoveryExecutor::new(
                        store.clone(),
                        root.clone(),
                        Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
                    );
                    let result = executor.recover(action);
                    assert_eq!(authority.provenance(), (1, 0));
                    assert!(authority.shutdown());
                    result
                } else {
                    let authority = TestRecoveryAuthority::new(2);
                    authority.provision_trusted_confirmation(&action);
                    let executor = H5RecoveryExecutor::new(
                        store.clone(),
                        root,
                        Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
                    );
                    executor.recover(action)
                };
                assert_eq!(
                    result.outcome,
                    if scenario == 7 {
                        RecoveryExecutionOutcome::RecoveredNoOp
                    } else {
                        RecoveryExecutionOutcome::Recovered
                    }
                );
                assert_eq!(result.mutation_count, if scenario == 7 { 0 } else { 1 });
                assert_eq!(fs::read(&current_path).unwrap(), BEFORE);
                assert_eq!(
                    store
                        .scan_transactions()
                        .unwrap()
                        .valid_transactions()
                        .next()
                        .unwrap()
                        .state(),
                    RecoveryTransactionState::RecoveredTerminal
                );
            }
            5 => {
                assert_eq!(
                    snapshot.state(),
                    RecoveryTransactionState::CommittedTerminal
                );
                assert_eq!(current, REPLACEMENT.as_bytes());
                assert_eq!(
                    fs::read(&store.recovery_root().join(format!(
                        "{}.recovered",
                        snapshot.journal().transaction_id().as_str()
                    )))
                    .is_err(),
                    true
                );
            }
            8 => {
                assert_eq!(
                    snapshot.state(),
                    RecoveryTransactionState::RecoveredTerminal
                );
                assert_eq!(current, BEFORE);
                assert!(store
                    .scan_transactions()
                    .unwrap()
                    .actionable_recovery_transactions()
                    .next()
                    .is_none());
            }
            _ => panic!("unknown H5-B crash scenario {scenario}"),
        }
        let _ = profile;
    }

    #[test]
    fn h5b_subprocess_crash_harness_proves_restart_states_and_fresh_recovery() {
        for scenario in 1..=8 {
            run_crash_case(scenario);
        }
    }

    #[test]
    fn production_registry_and_h5_namespace_are_test_only() {
        let source = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap()
                .join("src-tauri/src/capability/descriptor.rs"),
        )
        .unwrap();
        assert!(source.contains("Self::from_trusted_descriptors([])"));
        assert_eq!(H5_DESCRIPTOR_RISK_CLASS, "High");
        assert_eq!(H5_DESCRIPTOR_APPROVAL_FLOOR, "ExplicitPerAction");
        assert_eq!(H5_DESCRIPTOR_SCOPE_REQUIREMENT, "WorkspaceRequired");
    }
}
