//! Internal Windows-only coordination primitives for a future storage upgrade.
//!
//! These APIs deliberately do not open SQLite, run migrations, or participate
//! in `StorageService::initialize`. H1-A3 will decide when to invoke them
//! before its own transaction and final resource recheck.

/// A stable, deidentified failure category for the upgrade process gate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UpgradeGateError {
    UnsupportedPlatform,
    UpgradeMutexNameDerivationFailed,
    UpgradeExclusiveGateUnavailable,
    RestartManagerSessionFailed,
    RestartManagerRegistrationFailed,
    RestartManagerQueryFailed,
    ProcessIdentityReadFailed,
    ProcessVerificationFailed,
    LegacyWriterDetected,
}

impl UpgradeGateError {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "UNSUPPORTED_PLATFORM",
            Self::UpgradeMutexNameDerivationFailed => "UPGRADE_MUTEX_NAME_DERIVATION_FAILED",
            Self::UpgradeExclusiveGateUnavailable => "UPGRADE_EXCLUSIVE_GATE_UNAVAILABLE",
            Self::RestartManagerSessionFailed => "RESTART_MANAGER_SESSION_FAILED",
            Self::RestartManagerRegistrationFailed => "RESTART_MANAGER_REGISTRATION_FAILED",
            Self::RestartManagerQueryFailed => "RESTART_MANAGER_QUERY_FAILED",
            Self::ProcessIdentityReadFailed => "PROCESS_IDENTITY_READ_FAILED",
            Self::ProcessVerificationFailed => "PROCESS_VERIFICATION_FAILED",
            Self::LegacyWriterDetected => "LEGACY_WRITER_DETECTED",
        }
    }

    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "The upgrade process gate is only available on Windows.",
            Self::UpgradeMutexNameDerivationFailed => {
                "The upgrade mutex name could not be derived."
            }
            Self::UpgradeExclusiveGateUnavailable => {
                "The upgrade process gate is currently unavailable."
            }
            Self::RestartManagerSessionFailed => {
                "The upgrade process inspection session could not be started."
            }
            Self::RestartManagerRegistrationFailed => {
                "The upgrade process inspection resources could not be registered."
            }
            Self::RestartManagerQueryFailed => {
                "The upgrade process inspection could not be completed."
            }
            Self::ProcessIdentityReadFailed => {
                "The upgrade process identity could not be verified."
            }
            Self::ProcessVerificationFailed => {
                "The previously detected process state could not be verified."
            }
            Self::LegacyWriterDetected => "A legacy writer still has the storage resources open.",
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct ProcessInstanceId {
    pid: u32,
    creation_time: u64,
}

/// An opaque snapshot of non-current processes that held the database
/// resources during one Restart Manager inspection.
///
/// Its process identities are intentionally private so callers can retain the
/// snapshot for a later verification without receiving process details.
pub(crate) struct LegacyWriterSnapshot {
    #[cfg(windows)]
    processes: Vec<ProcessInstanceId>,
}

/// The result of a point-in-time legacy-writer inspection.
///
/// `Clear` describes only that inspection. It does not establish permanent
/// safety and does not replace H1-A3's transaction-bound final recheck.
pub(crate) enum LegacyWriterInspection {
    Clear,
    Occupied {
        count: usize,
        snapshot: LegacyWriterSnapshot,
    },
}

impl LegacyWriterInspection {
    pub(crate) const fn count(&self) -> usize {
        match self {
            Self::Clear => 0,
            Self::Occupied { count, .. } => *count,
        }
    }

    pub(crate) fn into_snapshot(self) -> Option<LegacyWriterSnapshot> {
        match self {
            Self::Clear => None,
            Self::Occupied { snapshot, .. } => Some(snapshot),
        }
    }
}

#[cfg(windows)]
mod windows;

#[cfg(windows)]
pub(crate) use windows::{
    acquire_upgrade_mutex, inspect_database_resource_occupants, verify_processes_terminated,
    WindowsUpgradeMutexGuard,
};

#[cfg(not(windows))]
mod unsupported {
    use super::{LegacyWriterInspection, LegacyWriterSnapshot, UpgradeGateError};

    /// Exists only to keep the narrow internal API platform-complete.
    pub(crate) struct WindowsUpgradeMutexGuard;

    pub(crate) fn acquire_upgrade_mutex(
        _database_path: &std::path::Path,
    ) -> Result<WindowsUpgradeMutexGuard, UpgradeGateError> {
        Err(UpgradeGateError::UnsupportedPlatform)
    }

    pub(crate) fn inspect_database_resource_occupants(
        _database_path: &std::path::Path,
    ) -> Result<LegacyWriterInspection, UpgradeGateError> {
        Err(UpgradeGateError::UnsupportedPlatform)
    }

    pub(crate) fn verify_processes_terminated(
        _snapshot: &LegacyWriterSnapshot,
    ) -> Result<LegacyWriterInspection, UpgradeGateError> {
        Err(UpgradeGateError::UnsupportedPlatform)
    }
}

#[cfg(not(windows))]
pub(crate) use unsupported::{
    acquire_upgrade_mutex, inspect_database_resource_occupants, verify_processes_terminated,
    WindowsUpgradeMutexGuard,
};

// Compile-time H1-A3 handoff contract. This references the narrow APIs without
// invoking them, so H1-A2 remains deliberately disconnected from storage
// initialization while signature drift is still caught during compilation.
type AcquireUpgradeMutexApi =
    fn(&std::path::Path) -> Result<WindowsUpgradeMutexGuard, UpgradeGateError>;
type InspectDatabaseResourceOccupantsApi =
    fn(&std::path::Path) -> Result<LegacyWriterInspection, UpgradeGateError>;
type VerifyProcessesTerminatedApi =
    fn(&LegacyWriterSnapshot) -> Result<LegacyWriterInspection, UpgradeGateError>;
type UpgradeGateErrorStringApi = fn(UpgradeGateError) -> &'static str;
type LegacyWriterInspectionCountApi = fn(&LegacyWriterInspection) -> usize;
type LegacyWriterSnapshotApi = fn(LegacyWriterInspection) -> Option<LegacyWriterSnapshot>;
type UpgradeGateH1A3ApiContract = (
    AcquireUpgradeMutexApi,
    InspectDatabaseResourceOccupantsApi,
    VerifyProcessesTerminatedApi,
    UpgradeGateErrorStringApi,
    UpgradeGateErrorStringApi,
    LegacyWriterInspectionCountApi,
    LegacyWriterSnapshotApi,
);

const _: UpgradeGateH1A3ApiContract = (
    acquire_upgrade_mutex,
    inspect_database_resource_occupants,
    verify_processes_terminated,
    UpgradeGateError::code,
    UpgradeGateError::message,
    LegacyWriterInspection::count,
    LegacyWriterInspection::into_snapshot,
);

// These two categories are produced by the non-Windows implementation and a
// future H1-A3 caller respectively; retain them in the stable error catalog on
// Windows builds without manufacturing a runtime result.
const _: [UpgradeGateError; 2] = [
    UpgradeGateError::UnsupportedPlatform,
    UpgradeGateError::LegacyWriterDetected,
];

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[test]
    fn upgrade_gate_non_windows_is_explicitly_unsupported() {
        let error = match acquire_upgrade_mutex(std::path::Path::new("storage.sqlite3")) {
            Err(error) => error,
            Ok(_) => panic!("the non-Windows upgrade gate must not report success"),
        };
        assert_eq!(error, UpgradeGateError::UnsupportedPlatform);
        assert_eq!(error.code(), "UNSUPPORTED_PLATFORM");
    }
}
