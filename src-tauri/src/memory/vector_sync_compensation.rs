//! Pure, no-I/O compensation pre-classification for vector sync.
//!
//! This module never touches SQLite, LanceDB, a provider, a runtime lease, or a
//! fence. It only maps caller-supplied facts into a stable, redacted class.
//! "Eligible" means a later fenced reconcile phase may re-verify authority; it
//! never grants write authority here.

#![allow(dead_code)]

use crate::{
    memory::vector_sync_outbox::{MemoryVectorSyncAction, MemoryVectorSyncState},
    vector_store::{VectorMetadataSample, VectorStoreError, VectorStoreErrorCode},
};

/// Deterministic first-error order for an exact proof comparison.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactGenerationMismatch {
    Generation,
    Life,
    Memory,
    Revision,
    ContentHash,
    Descriptor,
    Dimension,
}

/// Stable reason why an exact proof could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VectorProofUnavailableReason {
    StoreUnavailable,
    GenerationMissing,
    StoreCorrupt,
}

/// Result of comparing expected authoritative metadata against an observed
/// metadata sample. Holds no actual/expected values and no error text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactGenerationProof {
    Exact,
    Missing,
    Mismatch(ExactGenerationMismatch),
    Unavailable(VectorProofUnavailableReason),
}

/// Expected authoritative metadata. Borrows existing values, never owns
/// copies, and deliberately does not derive Debug or Serialize.
pub(crate) struct ExpectedGenerationMetadata<'a> {
    generation_id: &'a str,
    life_id: &'a str,
    memory_id: &'a str,
    memory_revision: i64,
    content_hash: &'a str,
    descriptor_hash: &'a str,
    dimension: usize,
}

impl<'a> ExpectedGenerationMetadata<'a> {
    pub(crate) fn new(
        generation_id: &'a str,
        life_id: &'a str,
        memory_id: &'a str,
        memory_revision: i64,
        content_hash: &'a str,
        descriptor_hash: &'a str,
        dimension: usize,
    ) -> Self {
        Self {
            generation_id,
            life_id,
            memory_id,
            memory_revision,
            content_hash,
            descriptor_hash,
            dimension,
        }
    }
}

/// Map an observed `VectorMetadataSample` (already read elsewhere) against the
/// expected authoritative values. Pure comparison only.
pub(crate) fn compare_exact_proof(
    expected: &ExpectedGenerationMetadata<'_>,
    observed: &VectorMetadataSample,
) -> ExactGenerationProof {
    if expected.generation_id != observed.generation_id {
        return ExactGenerationProof::Mismatch(ExactGenerationMismatch::Generation);
    }
    if expected.life_id != observed.life_id {
        return ExactGenerationProof::Mismatch(ExactGenerationMismatch::Life);
    }
    if expected.memory_id != observed.memory_id {
        return ExactGenerationProof::Mismatch(ExactGenerationMismatch::Memory);
    }
    if expected.memory_revision != observed.memory_revision {
        return ExactGenerationProof::Mismatch(ExactGenerationMismatch::Revision);
    }
    if expected.content_hash != observed.content_hash {
        return ExactGenerationProof::Mismatch(ExactGenerationMismatch::ContentHash);
    }
    if expected.descriptor_hash != observed.descriptor_hash {
        return ExactGenerationProof::Mismatch(ExactGenerationMismatch::Descriptor);
    }
    if expected.dimension != observed.dimension {
        return ExactGenerationProof::Mismatch(ExactGenerationMismatch::Dimension);
    }
    ExactGenerationProof::Exact
}

/// Map an already-completed VectorStore read result into an exact proof.
/// Never performs I/O here; the caller must have already issued the query.
pub(crate) fn map_vector_store_result(
    expected: &ExpectedGenerationMetadata<'_>,
    result: Result<Option<VectorMetadataSample>, VectorStoreError>,
) -> ExactGenerationProof {
    match result {
        Ok(Some(sample)) => compare_exact_proof(expected, &sample),
        Ok(None) => ExactGenerationProof::Missing,
        Err(error) => {
            let reason = match error.code {
                VectorStoreErrorCode::GenerationNotFound => {
                    VectorProofUnavailableReason::GenerationMissing
                }
                VectorStoreErrorCode::GenerationCorrupt => {
                    VectorProofUnavailableReason::StoreCorrupt
                }
                _ => VectorProofUnavailableReason::StoreUnavailable,
            };
            ExactGenerationProof::Unavailable(reason)
        }
    }
}

/// Send disposition facts, mirroring the durable outbox values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CompensationSendDisposition {
    None,
    DefinitelyNotSent,
    PossiblySent,
}

/// Caller-supplied facts about one outbox candidate. Owns nothing sensitive;
/// `error_code` and `migration_disposition` are stable fixed strings.
pub(crate) struct VectorSyncCompensationFacts<'a> {
    pub desired_action: MemoryVectorSyncAction,
    pub state: MemoryVectorSyncState,
    pub attempt_count: u32,
    pub last_send_disposition: CompensationSendDisposition,
    pub last_error_code: Option<&'a str>,
    pub migration_disposition: Option<&'a str>,
    pub has_complete_target_binding: bool,
    pub proof: ExactGenerationProof,
}

/// Stable redacted compensation class. "Eligible" only permits entering the
/// later fenced reconcile flow; it is not a completed/finalized outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum VectorSyncCompensationClass {
    EligibleForFencedUpsertFinalize,
    EligibleForFencedDeleteReplay,
    ManualOnlyProviderResultUnknown,
    ManualRebuildRequired,
    DeferredVectorStoreUnavailable,
    MigrationIsolated,
    NotEligible,
    InvariantViolation,
}

const STABLE_UNKNOWN: &str = "PROVIDER_RESULT_UNKNOWN";

/// Fail-closed classification. Order: migration isolation, target binding,
/// attempt count, action, state, disposition, error code, exact proof.
pub(crate) fn classify_compensation(
    facts: &VectorSyncCompensationFacts<'_>,
) -> VectorSyncCompensationClass {
    if facts.migration_disposition.is_some() {
        return VectorSyncCompensationClass::MigrationIsolated;
    }
    if !facts.has_complete_target_binding {
        return VectorSyncCompensationClass::InvariantViolation;
    }
    if facts.attempt_count == 0 {
        return VectorSyncCompensationClass::NotEligible;
    }
    match facts.desired_action {
        MemoryVectorSyncAction::Upsert => classify_upsert(facts),
        MemoryVectorSyncAction::Delete => classify_delete(facts),
    }
}

fn classify_upsert(facts: &VectorSyncCompensationFacts<'_>) -> VectorSyncCompensationClass {
    if facts.state != MemoryVectorSyncState::Blocked {
        return VectorSyncCompensationClass::NotEligible;
    }
    match facts.last_send_disposition {
        CompensationSendDisposition::None => VectorSyncCompensationClass::InvariantViolation,
        CompensationSendDisposition::DefinitelyNotSent => {
            if facts.last_error_code == Some(STABLE_UNKNOWN) {
                VectorSyncCompensationClass::InvariantViolation
            } else {
                VectorSyncCompensationClass::NotEligible
            }
        }
        CompensationSendDisposition::PossiblySent => {
            if facts.last_error_code != Some(STABLE_UNKNOWN) {
                return VectorSyncCompensationClass::NotEligible;
            }
            match facts.proof {
                ExactGenerationProof::Exact => {
                    VectorSyncCompensationClass::EligibleForFencedUpsertFinalize
                }
                ExactGenerationProof::Missing => {
                    VectorSyncCompensationClass::ManualOnlyProviderResultUnknown
                }
                ExactGenerationProof::Mismatch(_) => {
                    VectorSyncCompensationClass::ManualRebuildRequired
                }
                ExactGenerationProof::Unavailable(reason) => match reason {
                    VectorProofUnavailableReason::StoreUnavailable => {
                        VectorSyncCompensationClass::DeferredVectorStoreUnavailable
                    }
                    VectorProofUnavailableReason::GenerationMissing => {
                        VectorSyncCompensationClass::ManualOnlyProviderResultUnknown
                    }
                    VectorProofUnavailableReason::StoreCorrupt => {
                        VectorSyncCompensationClass::ManualRebuildRequired
                    }
                },
            }
        }
    }
}

fn classify_delete(facts: &VectorSyncCompensationFacts<'_>) -> VectorSyncCompensationClass {
    if facts.state != MemoryVectorSyncState::Pending {
        return VectorSyncCompensationClass::NotEligible;
    }
    match facts.last_send_disposition {
        CompensationSendDisposition::None => {
            VectorSyncCompensationClass::EligibleForFencedDeleteReplay
        }
        CompensationSendDisposition::PossiblySent => {
            VectorSyncCompensationClass::InvariantViolation
        }
        CompensationSendDisposition::DefinitelyNotSent => {
            VectorSyncCompensationClass::InvariantViolation
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected<'a>() -> ExpectedGenerationMetadata<'a> {
        ExpectedGenerationMetadata::new(
            "gen-a",
            "life-a",
            "mem-1",
            2,
            "content-hash-abc",
            "desc-hash-xyz",
            3,
        )
    }

    fn sample(
        gen: &str,
        life: &str,
        mem: &str,
        rev: i64,
        chash: &str,
        dhash: &str,
        dim: usize,
    ) -> VectorMetadataSample {
        VectorMetadataSample {
            generation_id: gen.to_owned(),
            life_id: life.to_owned(),
            memory_id: mem.to_owned(),
            memory_revision: rev,
            content_hash: chash.to_owned(),
            descriptor_hash: dhash.to_owned(),
            dimension: dim,
        }
    }

    #[test]
    fn exact_proof_exact_match() {
        let exp = expected();
        let obs = sample(
            "gen-a",
            "life-a",
            "mem-1",
            2,
            "content-hash-abc",
            "desc-hash-xyz",
            3,
        );
        assert_eq!(compare_exact_proof(&exp, &obs), ExactGenerationProof::Exact);
    }

    #[test]
    fn exact_proof_mismatch_first_error_order() {
        let exp = expected();
        let cases = [
            (
                ExactGenerationMismatch::Generation,
                "gen-b",
                "life-a",
                "mem-1",
                2,
                "content-hash-abc",
                "desc-hash-xyz",
                3,
            ),
            (
                ExactGenerationMismatch::Life,
                "gen-a",
                "life-b",
                "mem-1",
                2,
                "content-hash-abc",
                "desc-hash-xyz",
                3,
            ),
            (
                ExactGenerationMismatch::Memory,
                "gen-a",
                "life-a",
                "mem-2",
                2,
                "content-hash-abc",
                "desc-hash-xyz",
                3,
            ),
            (
                ExactGenerationMismatch::Revision,
                "gen-a",
                "life-a",
                "mem-1",
                3,
                "content-hash-abc",
                "desc-hash-xyz",
                3,
            ),
            (
                ExactGenerationMismatch::ContentHash,
                "gen-a",
                "life-a",
                "mem-1",
                2,
                "other-hash",
                "desc-hash-xyz",
                3,
            ),
            (
                ExactGenerationMismatch::Descriptor,
                "gen-a",
                "life-a",
                "mem-1",
                2,
                "content-hash-abc",
                "other-desc",
                3,
            ),
            (
                ExactGenerationMismatch::Dimension,
                "gen-a",
                "life-a",
                "mem-1",
                2,
                "content-hash-abc",
                "desc-hash-xyz",
                4,
            ),
        ];
        for (expected_mismatch, g, l, m, r, ch, dh, d) in cases {
            let obs = sample(g, l, m, r, ch, dh, d);
            assert_eq!(
                compare_exact_proof(&exp, &obs),
                ExactGenerationProof::Mismatch(expected_mismatch),
                "case {expected_mismatch:?}"
            );
        }
    }

    #[test]
    fn exact_proof_debug_leaks_no_identity_or_hash() {
        let exp = expected();
        let obs = sample(
            "gen-a",
            "life-a",
            "mem-1",
            2,
            "content-hash-abc",
            "desc-hash-xyz",
            3,
        );
        let proof = compare_exact_proof(&exp, &obs);
        let rendered = format!("{proof:?}");
        for canary in [
            "gen-a",
            "life-a",
            "mem-1",
            "content-hash-abc",
            "desc-hash-xyz",
            "2",
        ] {
            assert!(!rendered.contains(canary), "Debug leaked {canary}");
        }
        assert_eq!(rendered, "Exact");
    }

    #[test]
    fn map_vector_store_result_covers_all_codes() {
        let exp = expected();

        let exact = sample(
            "gen-a",
            "life-a",
            "mem-1",
            2,
            "content-hash-abc",
            "desc-hash-xyz",
            3,
        );
        assert_eq!(
            map_vector_store_result(&exp, Ok(Some(exact))),
            ExactGenerationProof::Exact
        );

        assert_eq!(
            map_vector_store_result(&exp, Ok(None)),
            ExactGenerationProof::Missing
        );

        let mk = |code| VectorStoreError::new(code, "redacted", false);
        assert_eq!(
            map_vector_store_result(&exp, Err(mk(VectorStoreErrorCode::GenerationNotFound))),
            ExactGenerationProof::Unavailable(VectorProofUnavailableReason::GenerationMissing)
        );
        assert_eq!(
            map_vector_store_result(&exp, Err(mk(VectorStoreErrorCode::GenerationCorrupt))),
            ExactGenerationProof::Unavailable(VectorProofUnavailableReason::StoreCorrupt)
        );
        assert_eq!(
            map_vector_store_result(&exp, Err(mk(VectorStoreErrorCode::StoreUnavailable))),
            ExactGenerationProof::Unavailable(VectorProofUnavailableReason::StoreUnavailable)
        );
        // Any other code maps conservatively to StoreUnavailable
        assert_eq!(
            map_vector_store_result(&exp, Err(mk(VectorStoreErrorCode::InternalError))),
            ExactGenerationProof::Unavailable(VectorProofUnavailableReason::StoreUnavailable)
        );
    }

    fn facts(
        action: MemoryVectorSyncAction,
        state: MemoryVectorSyncState,
        attempt: u32,
        send: CompensationSendDisposition,
        err: Option<&'static str>,
        migration: Option<&'static str>,
        binding: bool,
        proof: ExactGenerationProof,
    ) -> VectorSyncCompensationFacts<'static> {
        VectorSyncCompensationFacts {
            desired_action: action,
            state,
            attempt_count: attempt,
            last_send_disposition: send,
            last_error_code: err,
            migration_disposition: migration,
            has_complete_target_binding: binding,
            proof,
        }
    }

    #[test]
    fn upsert_classification_matrix() {
        use MemoryVectorSyncAction::Upsert;
        use MemoryVectorSyncState::{Blocked, Failed, Processing, RetryWait};
        use VectorSyncCompensationClass::*;

        let sd_none = CompensationSendDisposition::None;
        let sd_dns = CompensationSendDisposition::DefinitelyNotSent;
        let sd_ps = CompensationSendDisposition::PossiblySent;

        let cases = [
            (
                "exact + blocked unknown + possibly_sent",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                EligibleForFencedUpsertFinalize,
            ),
            (
                "missing proof",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                ManualOnlyProviderResultUnknown,
            ),
            (
                "revision mismatch",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Mismatch(ExactGenerationMismatch::Revision),
                ),
                ManualRebuildRequired,
            ),
            (
                "store unavailable",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Unavailable(
                        VectorProofUnavailableReason::StoreUnavailable,
                    ),
                ),
                DeferredVectorStoreUnavailable,
            ),
            (
                "generation missing",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Unavailable(
                        VectorProofUnavailableReason::GenerationMissing,
                    ),
                ),
                ManualOnlyProviderResultUnknown,
            ),
            (
                "store corrupt",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Unavailable(VectorProofUnavailableReason::StoreCorrupt),
                ),
                ManualRebuildRequired,
            ),
            (
                "attempt=0",
                facts(
                    Upsert,
                    Blocked,
                    0,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                NotEligible,
            ),
            (
                "send=NULL",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_none,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                InvariantViolation,
            ),
            (
                "send=definitely_not_sent + unknown",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_dns,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                InvariantViolation,
            ),
            (
                "send=definitely_not_sent + retryable",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_dns,
                    Some("PROVIDER_UNAVAILABLE"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                NotEligible,
            ),
            (
                "wrong state processing",
                facts(
                    Upsert,
                    Processing,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                NotEligible,
            ),
            (
                "wrong state retry_wait",
                facts(
                    Upsert,
                    RetryWait,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                NotEligible,
            ),
            (
                "wrong state failed",
                facts(
                    Upsert,
                    Failed,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                NotEligible,
            ),
            (
                "wrong error code",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("LANCE_PERMANENT"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                NotEligible,
            ),
            (
                "migration isolated",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    Some("legacy_upsert_rebuild_required"),
                    true,
                    ExactGenerationProof::Exact,
                ),
                MigrationIsolated,
            ),
            (
                "incomplete binding",
                facts(
                    Upsert,
                    Blocked,
                    2,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    false,
                    ExactGenerationProof::Exact,
                ),
                InvariantViolation,
            ),
        ];

        for (name, input, expected) in cases {
            assert_eq!(classify_compensation(&input), expected, "case {name}");
        }
    }

    #[test]
    fn delete_classification_matrix() {
        use MemoryVectorSyncAction::Delete;
        use MemoryVectorSyncState::{Blocked, Failed, Pending, Processing, RetryWait};
        use VectorSyncCompensationClass::*;

        let sd_none = CompensationSendDisposition::None;
        let sd_ps = CompensationSendDisposition::PossiblySent;
        let sd_dns = CompensationSendDisposition::DefinitelyNotSent;

        let cases = [
            (
                "pending + attempt>0 + send=NULL",
                facts(
                    Delete,
                    Pending,
                    3,
                    sd_none,
                    None,
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                EligibleForFencedDeleteReplay,
            ),
            (
                "attempt=0",
                facts(
                    Delete,
                    Pending,
                    0,
                    sd_none,
                    None,
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                NotEligible,
            ),
            (
                "send=possibly_sent",
                facts(
                    Delete,
                    Pending,
                    3,
                    sd_ps,
                    None,
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                InvariantViolation,
            ),
            (
                "send=definitely_not_sent",
                facts(
                    Delete,
                    Pending,
                    3,
                    sd_dns,
                    None,
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                InvariantViolation,
            ),
            (
                "processing",
                facts(
                    Delete,
                    Processing,
                    3,
                    sd_none,
                    None,
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                NotEligible,
            ),
            (
                "retry_wait",
                facts(
                    Delete,
                    RetryWait,
                    3,
                    sd_none,
                    None,
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                NotEligible,
            ),
            (
                "blocked",
                facts(
                    Delete,
                    Blocked,
                    3,
                    sd_none,
                    None,
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                NotEligible,
            ),
            (
                "failed",
                facts(
                    Delete,
                    Failed,
                    3,
                    sd_none,
                    None,
                    None,
                    true,
                    ExactGenerationProof::Missing,
                ),
                NotEligible,
            ),
            (
                "migration isolated",
                facts(
                    Delete,
                    Pending,
                    3,
                    sd_none,
                    None,
                    Some("legacy_upsert_rebuild_required"),
                    true,
                    ExactGenerationProof::Missing,
                ),
                MigrationIsolated,
            ),
            (
                "incomplete binding",
                facts(
                    Delete,
                    Pending,
                    3,
                    sd_none,
                    None,
                    None,
                    false,
                    ExactGenerationProof::Missing,
                ),
                InvariantViolation,
            ),
        ];

        for (name, input, expected) in cases {
            assert_eq!(classify_compensation(&input), expected, "case {name}");
        }
    }

    #[test]
    fn classification_debug_leaks_no_sensitive_values() {
        use MemoryVectorSyncAction::Upsert;
        use MemoryVectorSyncState::Blocked;
        let input = facts(
            Upsert,
            Blocked,
            2,
            CompensationSendDisposition::PossiblySent,
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Exact,
        );
        let class = classify_compensation(&input);
        let rendered = format!("{class:?}");
        for canary in [
            "life",
            "mem",
            "content",
            "desc",
            "gen-",
            "PROVIDER_RESULT_UNKNOWN",
        ] {
            assert!(
                !rendered.contains(canary),
                "Debug leaked {canary}: {rendered}"
            );
        }
        assert_eq!(rendered, "EligibleForFencedUpsertFinalize");
    }

    #[test]
    fn no_provider_retry_classification_exists() {
        // The classifier's vocabulary must never include a provider-retry class.
        let debug_of_enum = format!(
            "{:?}",
            VectorSyncCompensationClass::EligibleForFencedUpsertFinalize
        );
        let variants = [
            "EligibleForFencedUpsertFinalize",
            "EligibleForFencedDeleteReplay",
            "ManualOnlyProviderResultUnknown",
            "ManualRebuildRequired",
            "DeferredVectorStoreUnavailable",
            "MigrationIsolated",
            "NotEligible",
            "InvariantViolation",
        ];
        assert!(variants.contains(&debug_of_enum.as_str()));
    }
}
