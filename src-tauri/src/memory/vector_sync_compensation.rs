//! Pure, no-I/O compensation pre-classification for vector sync.
//!
//! This module never touches SQLite, LanceDB, a provider, a runtime lease, or a
//! fence. It only maps caller-supplied facts into a stable, redacted class.
//! "Eligible" means a later fenced reconcile phase may re-verify authority; it
//! never grants write authority here.

#![allow(dead_code)]

use crate::{
    memory::vector_sync_outbox::{MemoryVectorSyncAction, MemoryVectorSyncState},
    storage::MAX_VECTOR_SYNC_ATTEMPTS,
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
///
/// The error-code match is exhaustive on every current `VectorStoreErrorCode`
/// variant. Only `StoreUnavailable` is classified as a transient environment
/// failure; `VectorReadFailed` deliberately mixes I/O and malformed-column
/// semantics so it is conservatively classified as corruption instead of
/// being deferred as if the store were merely temporarily unavailable.
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
                VectorStoreErrorCode::StoreUnavailable => {
                    VectorProofUnavailableReason::StoreUnavailable
                }
                VectorStoreErrorCode::GenerationCorrupt
                | VectorStoreErrorCode::GenerationSchemaMismatch
                | VectorStoreErrorCode::GenerationDimensionMismatch
                | VectorStoreErrorCode::GenerationDescriptorMismatch
                | VectorStoreErrorCode::RecordInvalid
                | VectorStoreErrorCode::VectorInvalid
                | VectorStoreErrorCode::VectorDimensionMismatch
                | VectorStoreErrorCode::InvalidVector
                | VectorStoreErrorCode::DimensionMismatch
                | VectorStoreErrorCode::InvalidLimit
                | VectorStoreErrorCode::InvalidScoreThreshold
                | VectorStoreErrorCode::VectorNotFound
                | VectorStoreErrorCode::InternalError
                | VectorStoreErrorCode::InvalidIdentifier
                | VectorStoreErrorCode::GenerationIdInvalid
                | VectorStoreErrorCode::VectorWriteFailed
                | VectorStoreErrorCode::VectorDeleteFailed
                | VectorStoreErrorCode::VectorReadFailed
                | VectorStoreErrorCode::GenerationDropFailed
                | VectorStoreErrorCode::GenerationLocked
                | VectorStoreErrorCode::GenerationDropRequiresRegistry => {
                    VectorProofUnavailableReason::StoreCorrupt
                }
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
///
/// `attempt_count` is signed so SQLite anomaly values (negative or over-budget
/// counts) can be represented and rejected instead of being silently clamped.
pub(crate) struct VectorSyncCompensationFacts<'a> {
    pub desired_action: MemoryVectorSyncAction,
    pub state: MemoryVectorSyncState,
    pub attempt_count: i64,
    pub fenced_claim_epoch: i64,
    pub last_marked_claim_epoch: i64,
    pub has_claimed_generation: bool,
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
    /// An upsert whose durable evidence cannot rule out a provider send.
    BlockedUnknownSend,
    /// The mutation has exhausted its five-slot attempt budget.
    AttemptsAtLimit,
    /// A pre-schema-14 `(0,0)` processing row with unproven external effects.
    LegacyUnproven,
    /// A delete candidate whose safe replay cannot be proven at this stage.
    LateDeleteUnproven,
    /// The row is already terminal or the current mutation is already done.
    AlreadyCurrentOrCompleted,
}

const STABLE_UNKNOWN: &str = "PROVIDER_RESULT_UNKNOWN";

/// Fail-closed classification. Order: migration isolation, invalid identity,
/// legacy provenance, target binding, unknown-send evidence, attempt budget,
/// terminal state, action-specific classification.
pub(crate) fn classify_compensation(
    facts: &VectorSyncCompensationFacts<'_>,
) -> VectorSyncCompensationClass {
    if facts.migration_disposition.is_some() {
        return VectorSyncCompensationClass::MigrationIsolated;
    }
    if invalid_attempt_identity(facts) {
        return VectorSyncCompensationClass::InvariantViolation;
    }
    if facts.fenced_claim_epoch == 0
        && facts.last_marked_claim_epoch == 0
        && facts.state == MemoryVectorSyncState::Processing
    {
        return VectorSyncCompensationClass::LegacyUnproven;
    }
    if !facts.has_complete_target_binding {
        return VectorSyncCompensationClass::InvariantViolation;
    }
    // Unknown Send evidence outranks every budget, terminal, and eligible
    // classification: a possibly-sent result or a PROVIDER_RESULT_UNKNOWN
    // error can never be automatically compensated or replayed.
    if has_unknown_send_evidence(facts) {
        return match facts.desired_action {
            MemoryVectorSyncAction::Upsert => VectorSyncCompensationClass::BlockedUnknownSend,
            MemoryVectorSyncAction::Delete => VectorSyncCompensationClass::LateDeleteUnproven,
        };
    }
    if facts.attempt_count > MAX_VECTOR_SYNC_ATTEMPTS {
        return VectorSyncCompensationClass::InvariantViolation;
    }
    if facts.attempt_count == MAX_VECTOR_SYNC_ATTEMPTS {
        return VectorSyncCompensationClass::AttemptsAtLimit;
    }
    if facts.attempt_count == 0 {
        return VectorSyncCompensationClass::NotEligible;
    }
    if facts.state == MemoryVectorSyncState::Failed {
        return VectorSyncCompensationClass::AlreadyCurrentOrCompleted;
    }
    match facts.desired_action {
        MemoryVectorSyncAction::Upsert => classify_upsert(facts),
        MemoryVectorSyncAction::Delete => classify_delete(facts),
    }
}

/// True when durable evidence cannot rule out a provider send.
fn has_unknown_send_evidence(facts: &VectorSyncCompensationFacts<'_>) -> bool {
    facts.last_send_disposition == CompensationSendDisposition::PossiblySent
        || facts.last_error_code == Some(STABLE_UNKNOWN)
}

/// True when the durable attempt identity violates schema-14 invariants.
fn invalid_attempt_identity(facts: &VectorSyncCompensationFacts<'_>) -> bool {
    facts.attempt_count < 0
        || facts.attempt_count > MAX_VECTOR_SYNC_ATTEMPTS
        || facts.fenced_claim_epoch < 0
        || facts.last_marked_claim_epoch < 0
        || facts.last_marked_claim_epoch > facts.fenced_claim_epoch
        || (facts.last_marked_claim_epoch > 0 && facts.attempt_count == 0)
        || (facts.attempt_count > 0 && !facts.has_claimed_generation)
}

fn classify_upsert(facts: &VectorSyncCompensationFacts<'_>) -> VectorSyncCompensationClass {
    if facts.state != MemoryVectorSyncState::Blocked {
        return VectorSyncCompensationClass::NotEligible;
    }
    match facts.last_send_disposition {
        CompensationSendDisposition::None => VectorSyncCompensationClass::InvariantViolation,
        CompensationSendDisposition::DefinitelyNotSent => {
            // A retryable definitely-not-sent failure is ordinary drain work,
            // not S3 compensation.
            VectorSyncCompensationClass::NotEligible
        }
        CompensationSendDisposition::PossiblySent => {
            // Unknown Send evidence is handled at the top level; this branch is
            // unreachable through classify_compensation but fails closed.
            VectorSyncCompensationClass::BlockedUnknownSend
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
            VectorSyncCompensationClass::LateDeleteUnproven
        }
        CompensationSendDisposition::DefinitelyNotSent => {
            VectorSyncCompensationClass::LateDeleteUnproven
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

        // Exhaustive table over every current VectorStoreErrorCode variant.
        // The count below is the source-of-truth census from vector_store/mod.rs.
        let cases: &[(VectorStoreErrorCode, VectorProofUnavailableReason)] = &[
            (
                VectorStoreErrorCode::InvalidVector,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::DimensionMismatch,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::InvalidLimit,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::InvalidScoreThreshold,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::VectorNotFound,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::StoreUnavailable,
                VectorProofUnavailableReason::StoreUnavailable,
            ),
            (
                VectorStoreErrorCode::InternalError,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::InvalidIdentifier,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::GenerationIdInvalid,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::GenerationNotFound,
                VectorProofUnavailableReason::GenerationMissing,
            ),
            (
                VectorStoreErrorCode::GenerationSchemaMismatch,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::GenerationDimensionMismatch,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::GenerationDescriptorMismatch,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::RecordInvalid,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::VectorInvalid,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::VectorDimensionMismatch,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::VectorWriteFailed,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::VectorDeleteFailed,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::VectorReadFailed,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::GenerationDropFailed,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::GenerationLocked,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::GenerationCorrupt,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
            (
                VectorStoreErrorCode::GenerationDropRequiresRegistry,
                VectorProofUnavailableReason::StoreCorrupt,
            ),
        ];

        // 23 variants currently exist in the source enum.
        assert_eq!(cases.len(), 23, "enum census drift");

        for (code, expected_reason) in cases {
            let proof = map_vector_store_result(&exp, Err(mk(*code)));
            assert_eq!(
                proof,
                ExactGenerationProof::Unavailable(*expected_reason),
                "case {code:?}"
            );
        }
    }

    #[test]
    fn map_vector_store_result_representative_semantic_categories() {
        let exp = expected();
        let mk = |code| VectorStoreError::new(code, "redacted", false);

        let assert_reason = |code, reason| {
            assert_eq!(
                map_vector_store_result(&exp, Err(mk(code))),
                ExactGenerationProof::Unavailable(reason),
                "case {code:?}"
            );
        };

        // GenerationMissing set
        assert_reason(
            VectorStoreErrorCode::GenerationNotFound,
            VectorProofUnavailableReason::GenerationMissing,
        );

        // StoreUnavailable set
        assert_reason(
            VectorStoreErrorCode::StoreUnavailable,
            VectorProofUnavailableReason::StoreUnavailable,
        );

        // StoreCorrupt set (deterministic/structural)
        assert_reason(
            VectorStoreErrorCode::GenerationCorrupt,
            VectorProofUnavailableReason::StoreCorrupt,
        );
        assert_reason(
            VectorStoreErrorCode::GenerationSchemaMismatch,
            VectorProofUnavailableReason::StoreCorrupt,
        );
        assert_reason(
            VectorStoreErrorCode::GenerationDimensionMismatch,
            VectorProofUnavailableReason::StoreCorrupt,
        );
        assert_reason(
            VectorStoreErrorCode::GenerationDescriptorMismatch,
            VectorProofUnavailableReason::StoreCorrupt,
        );
        assert_reason(
            VectorStoreErrorCode::RecordInvalid,
            VectorProofUnavailableReason::StoreCorrupt,
        );
        assert_reason(
            VectorStoreErrorCode::VectorReadFailed,
            VectorProofUnavailableReason::StoreCorrupt,
        );
        assert_reason(
            VectorStoreErrorCode::GenerationLocked,
            VectorProofUnavailableReason::StoreCorrupt,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn facts(
        action: MemoryVectorSyncAction,
        state: MemoryVectorSyncState,
        attempt: i64,
        send: CompensationSendDisposition,
        err: Option<&'static str>,
        migration: Option<&'static str>,
        binding: bool,
        proof: ExactGenerationProof,
    ) -> VectorSyncCompensationFacts<'static> {
        facts_with_epochs(
            action,
            state,
            attempt,
            2,
            2,
            attempt > 0,
            send,
            err,
            migration,
            binding,
            proof,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn facts_with_epochs(
        action: MemoryVectorSyncAction,
        state: MemoryVectorSyncState,
        attempt: i64,
        fenced_claim_epoch: i64,
        last_marked_claim_epoch: i64,
        has_claimed_generation: bool,
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
            fenced_claim_epoch,
            last_marked_claim_epoch,
            has_claimed_generation,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
            ),
            (
                "attempt=0",
                facts_with_epochs(
                    Upsert,
                    Blocked,
                    0,
                    0,
                    0,
                    false,
                    sd_ps,
                    Some("PROVIDER_RESULT_UNKNOWN"),
                    None,
                    true,
                    ExactGenerationProof::Exact,
                ),
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                BlockedUnknownSend,
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
                facts_with_epochs(
                    Delete,
                    Pending,
                    0,
                    0,
                    0,
                    false,
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
                LateDeleteUnproven,
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
                LateDeleteUnproven,
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
                AlreadyCurrentOrCompleted,
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
        assert_eq!(rendered, "BlockedUnknownSend");
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
            "BlockedUnknownSend",
            "AttemptsAtLimit",
            "LegacyUnproven",
            "LateDeleteUnproven",
            "AlreadyCurrentOrCompleted",
        ];
        assert!(variants.contains(&debug_of_enum.as_str()));
    }

    #[test]
    fn attempt_budget_classification_is_stable() {
        use MemoryVectorSyncAction::Delete;
        use MemoryVectorSyncState::Pending;

        // attempt == 5 is a legal exhausted budget
        let at_limit = facts(
            Delete,
            Pending,
            5,
            sd_none(),
            None,
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&at_limit),
            VectorSyncCompensationClass::AttemptsAtLimit
        );

        // attempt > 5 is an internal invariant violation
        let over_limit = facts(
            Delete,
            Pending,
            6,
            sd_none(),
            None,
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&over_limit),
            VectorSyncCompensationClass::InvariantViolation
        );
    }

    #[test]
    fn legacy_zero_epoch_processing_is_unproven() {
        use MemoryVectorSyncAction::Upsert;
        use MemoryVectorSyncState::Processing;
        let legacy = facts_with_epochs(
            Upsert,
            Processing,
            1,
            0,
            0,
            true,
            sd_ps(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&legacy),
            VectorSyncCompensationClass::LegacyUnproven
        );
    }

    #[test]
    fn invalid_attempt_identity_fails_closed() {
        use MemoryVectorSyncAction::Upsert;
        use MemoryVectorSyncState::Blocked;

        // last_marked > fenced is structurally invalid
        let invalid_epochs = facts_with_epochs(
            Upsert,
            Blocked,
            2,
            1,
            2,
            true,
            sd_ps(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Exact,
        );
        assert_eq!(
            classify_compensation(&invalid_epochs),
            VectorSyncCompensationClass::InvariantViolation
        );

        // last_marked > 0 with attempt == 0 is invalid
        let marked_but_zero_attempts = facts_with_epochs(
            Upsert,
            Blocked,
            0,
            3,
            3,
            false,
            sd_none(),
            None,
            None,
            true,
            ExactGenerationProof::Exact,
        );
        assert_eq!(
            classify_compensation(&marked_but_zero_attempts),
            VectorSyncCompensationClass::InvariantViolation
        );

        // attempt > 0 without a claimed generation is invalid
        let attempts_without_generation = facts_with_epochs(
            Upsert,
            Blocked,
            2,
            2,
            2,
            false,
            sd_ps(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Exact,
        );
        assert_eq!(
            classify_compensation(&attempts_without_generation),
            VectorSyncCompensationClass::InvariantViolation
        );
    }

    /// B1: a Delete carrying Unknown Send evidence is `LateDeleteUnproven` and
    /// can never become `EligibleForFencedDeleteReplay`, regardless of proof.
    #[test]
    fn late_delete_unproven_never_becomes_replay_eligible() {
        use MemoryVectorSyncAction::Delete;
        use MemoryVectorSyncState::Pending;

        let unproven = facts(
            Delete,
            Pending,
            3,
            sd_ps(),
            None,
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&unproven),
            VectorSyncCompensationClass::LateDeleteUnproven
        );
        // Even with an exact generation proof, Unknown Send evidence still
        // cannot be turned into a replay permit.
        let unproven_with_exact_proof = facts(
            Delete,
            Pending,
            3,
            sd_ps(),
            None,
            None,
            true,
            ExactGenerationProof::Exact,
        );
        assert_eq!(
            classify_compensation(&unproven_with_exact_proof),
            VectorSyncCompensationClass::LateDeleteUnproven
        );
    }

    #[test]
    fn terminal_failed_state_is_already_current_or_completed() {
        use MemoryVectorSyncAction::Delete;
        use MemoryVectorSyncState::Failed;
        let terminal = facts(
            Delete,
            Failed,
            3,
            sd_none(),
            None,
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&terminal),
            VectorSyncCompensationClass::AlreadyCurrentOrCompleted
        );
    }

    /// B1: Unknown Send evidence outranks budget, terminal, proof, and
    /// Eligible outcomes for Upsert and Delete alike. The upsert side stays
    /// `BlockedUnknownSend` under every stronger-looking signal.
    #[test]
    fn blocked_unknown_send_outranks_proof_budget_and_terminal_state() {
        use MemoryVectorSyncAction::{Delete, Upsert};
        use MemoryVectorSyncState::{Blocked, Failed, Pending, Processing};

        // Upsert possibly_sent + Exact proof + count 5 -> Blocked (not AttemptsAtLimit)
        let upsert_at_limit_unknown = facts(
            Upsert,
            Blocked,
            5,
            sd_ps(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Exact,
        );
        assert_eq!(
            classify_compensation(&upsert_at_limit_unknown),
            VectorSyncCompensationClass::BlockedUnknownSend
        );

        // Upsert unknown + Failed state -> Blocked (not AlreadyCurrentOrCompleted)
        let upsert_failed_unknown = facts(
            Upsert,
            Failed,
            2,
            sd_ps(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Exact,
        );
        assert_eq!(
            classify_compensation(&upsert_failed_unknown),
            VectorSyncCompensationClass::BlockedUnknownSend
        );

        // Upsert possibly_sent with an otherwise-eligible pending processing
        // state -> Blocked (not NotEligible).
        let upsert_processing_unknown = facts(
            Upsert,
            Processing,
            2,
            sd_ps(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Exact,
        );
        assert_eq!(
            classify_compensation(&upsert_processing_unknown),
            VectorSyncCompensationClass::BlockedUnknownSend
        );

        // Delete PROVIDER_RESULT_UNKNOWN + send NULL -> LateDeleteUnproven
        // (not EligibleForFencedDeleteReplay) even though otherwise eligible.
        let delete_unknown_null_send = facts(
            Delete,
            Pending,
            2,
            sd_none(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&delete_unknown_null_send),
            VectorSyncCompensationClass::LateDeleteUnproven
        );

        // Delete possibly_sent + count < 5 -> LateDeleteUnproven.
        let delete_possibly_sent = facts(
            Delete,
            Pending,
            2,
            sd_ps(),
            None,
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&delete_possibly_sent),
            VectorSyncCompensationClass::LateDeleteUnproven
        );

        // Delete unknown + count == 5 -> LateDeleteUnproven (not AttemptsAtLimit).
        let delete_unknown_at_limit = facts(
            Delete,
            Pending,
            5,
            sd_ps(),
            Some("PROVIDER_RESULT_UNKNOWN"),
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&delete_unknown_at_limit),
            VectorSyncCompensationClass::LateDeleteUnproven
        );
    }

    /// B2: negative attempt counts are structurally invalid and fail closed.
    #[test]
    fn negative_attempt_count_is_invariant_violation() {
        use MemoryVectorSyncAction::Delete;
        use MemoryVectorSyncState::Pending;
        let negative = facts_with_epochs(
            Delete,
            Pending,
            -1,
            2,
            2,
            true,
            sd_none(),
            None,
            None,
            true,
            ExactGenerationProof::Missing,
        );
        assert_eq!(
            classify_compensation(&negative),
            VectorSyncCompensationClass::InvariantViolation
        );
    }

    fn sd_none() -> CompensationSendDisposition {
        CompensationSendDisposition::None
    }

    fn sd_ps() -> CompensationSendDisposition {
        CompensationSendDisposition::PossiblySent
    }
}
