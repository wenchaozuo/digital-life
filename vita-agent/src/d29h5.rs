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
use std::sync::{Arc, Mutex};

use crate::recovery_journal::{
    RecoveryJournalError, RecoveryJournalIdentity, RecoveryJournalStore, RecoveryJournalV1,
    RecoveryMarkerState, RecoveryMarkerV1, RecoveryTransactionId, RecoveryTransactionScan,
    RecoveryTransactionSnapshot, RecoveryTransactionState, RECOVERY_JOURNAL_MAX_PREIMAGE_BYTES,
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

#[derive(Debug)]
pub(crate) struct H5ReplaceExecutionResult {
    pub journal: RecoveryJournalV1,
    pub native_outcome: WorkspaceReplaceCommitOutcome,
    pub commit_marker_persisted: bool,
    pub commit_unknown: bool,
}

struct H5StartedFence<'a> {
    store: &'a RecoveryJournalStore,
    journal: &'a RecoveryJournalV1,
    host_fence: &'a mut dyn WorkspaceReplaceCommitFence,
    started_persisted: bool,
}

impl WorkspaceReplaceCommitFence for H5StartedFence<'_> {
    fn check(&mut self) -> Result<(), WorkspaceReplaceFenceError> {
        if self.started_persisted {
            return Err(WorkspaceReplaceFenceError::Error);
        }
        self.host_fence.check()?;
        self.store
            .persist_started(self.journal)
            .map_err(|_| WorkspaceReplaceFenceError::Error)?;
        self.started_persisted = true;
        Ok(())
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

    pub(crate) fn disable_same_sqlite_authorization(&self) -> i64 {
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

pub(crate) fn execute_h5b_replace_after_host_pass(
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
    let journal = store.create_prepared(&target, context)?;
    let mut started_fence = H5StartedFence {
        store,
        journal: &journal,
        host_fence: fence,
        started_persisted: false,
    };
    let outcome = target.replace_existing_file_utf8_bounded_with_cancellation(
        expected_sha256,
        replacement,
        &mut started_fence,
        cancellation,
    );
    let mut commit_marker_persisted = false;
    let mut commit_unknown = false;
    if matches!(outcome, WorkspaceReplaceCommitOutcome::Committed { .. }) {
        let commit_marker = if force_commit_marker_failure {
            Err(RecoveryJournalError::InjectedFault("commit marker"))
        } else {
            store.persist_committed(&journal)
        };
        match commit_marker {
            Ok(_) => commit_marker_persisted = true,
            Err(_) => commit_unknown = true,
        }
    }
    Ok(H5ReplaceExecutionResult {
        journal,
        native_outcome: outcome,
        commit_marker_persisted,
        commit_unknown,
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
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tempfile::{tempdir, TempDir};

    const BEFORE: &[u8] = b"H5-B before\n";
    const REPLACEMENT: &str = "H5-B replacement\n";

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

    fn allow_fence() -> impl WorkspaceReplaceCommitFence {
        || Ok(())
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
            self.inner.disable_same_sqlite_authorization();
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
    fn started_marker_is_persisted_after_host_fence_and_before_h4_post_fence() {
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
        assert!(matches!(
            result.native_outcome,
            WorkspaceReplaceCommitOutcome::Committed { .. }
        ));
        assert!(result.commit_marker_persisted);
        assert!(!result.commit_unknown);
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
        )
        .unwrap();
        assert!(matches!(
            result.native_outcome,
            WorkspaceReplaceCommitOutcome::Committed { .. }
        ));
        assert!(!result.commit_marker_persisted);
        assert!(result.commit_unknown);
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
    fn disabled_same_sqlite_authorization_denies_after_grant_before_restore() {
        let fixture = Fixture::new();
        let journal = fixture.prepared_started();
        fixture.write_replacement();
        let authority = TestRecoveryAuthority::new(2);
        let action = fixture.action(&journal);
        authority.provision_trusted_confirmation(&action);
        authority.disable_same_sqlite_authorization();
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
    fn ambiguous_prepared_target_has_no_h5_recovery_candidate() {
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
        assert!(scan.has_ambiguous_target());
        assert_eq!(scan.valid_transactions().count(), 0);
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
        let journal = store
            .create_prepared(
                &root.prepare_target(Path::new("target.txt")).unwrap(),
                context,
            )
            .unwrap();
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
                    &sha256_hex(BEFORE),
                    REPLACEMENT,
                    &mut fence,
                    &cancellation,
                    WorkspaceReplaceTestFault::AbortAfterFirstMutation,
                );
                std::process::abort();
            }
            let outcome = target.replace_existing_file_utf8_bounded_with_cancellation(
                &sha256_hex(BEFORE),
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
                    executor
                        .scan()
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
                let authority = TestRecoveryAuthority::new(2);
                let action = RecoveryActionRequest::from_snapshot(
                    &snapshot,
                    &current,
                    &format!("parent-recovery-{scenario}"),
                    2,
                );
                authority.provision_trusted_confirmation(&action);
                let executor = H5RecoveryExecutor::new(
                    store.clone(),
                    root,
                    Arc::clone(&authority) as Arc<dyn RecoveryAuthorityPort>,
                );
                let result = executor.recover(action);
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
                    executor
                        .scan()
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
