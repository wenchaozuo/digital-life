use rusqlite::{params, Connection, OptionalExtension, Row, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

use crate::memory::{
    candidate_service::contains_prohibited_content,
    existing_generation_binding::ExistingGenerationBindingError,
    vector_sync_outbox::{
        ClaimMemoryVectorSyncLeaseRequest, ClaimMemoryVectorSyncRequest,
        EnqueueMemoryVectorSyncRequest, MemoryVectorSyncAction, MemoryVectorSyncJob,
        MemoryVectorSyncOutboxError, MemoryVectorSyncOutboxErrorCode,
        MemoryVectorSyncOutboxRepository, MemoryVectorSyncState,
    },
};
use crate::vector_store::{VectorGenerationContext, VectorGenerationId};

use super::{late_delete_resolution, StorageService};

const COLUMNS: &str = "id, life_id, memory_id, desired_action, state, attempt_count, next_attempt_at, lease_owner, lease_expires_at, last_error_code, created_at, updated_at";

/// The authoritative SQLite-side Attempt budget (Attempt Policy V1).
///
/// An Attempt is one durably reserved external-side-effect slot for the current
/// mutation, keyed by `(life_id, memory_id, mutation_sequence)`. The budget is
/// deliberately not configurable: it is not read from settings, the environment,
/// the frontend, or the worker. The worker and health modules keep their own
/// same-valued constants for their own retry classification; unifying them is
/// explicitly out of scope for ATT-I2.
pub(crate) const MAX_VECTOR_SYNC_ATTEMPTS: i64 = 5;

/// Canonical SQLite predicate for a Delete whose current mutation has crossed
/// an external boundary without a durable result. Such a row is a
/// `LateDeleteUnproven` candidate: ordinary claim, retry, reserve, and worker
/// paths must not replay it.
pub(super) const DELETE_UNKNOWN_EVIDENCE_SQL: &str = "desired_action='delete' AND (COALESCE(last_send_disposition, '')='possibly_sent' OR COALESCE(last_error_code, '')='PROVIDER_RESULT_UNKNOWN')";

/// The Rust counterpart of [`DELETE_UNKNOWN_EVIDENCE_SQL`]. Keep this narrow:
/// `definitely_not_sent` is explicit evidence that the Delete did not cross the
/// external boundary and is therefore not an Unknown Delete witness.
pub(crate) fn is_delete_unknown_evidence(
    desired_action: &str,
    last_send_disposition: Option<&str>,
    last_error_code: Option<&str>,
) -> bool {
    desired_action == "delete"
        && (last_send_disposition == Some("possibly_sent")
            || last_error_code == Some("PROVIDER_RESULT_UNKNOWN"))
}

/// Proof that one Attempt slot is durably reserved for exactly one claim.
///
/// The token is produced only by the single authoritative reserve path after its
/// transaction commits, so it can never describe an unreserved Attempt. It binds
/// every identity the reservation was made under, which is what lets ATT-I3
/// re-verify currency immediately before external I/O.
///
/// It deliberately has no public constructor, no `Serialize`/`Deserialize`, no
/// `Clone`, and no `Debug`: it must not reach IPC, logs, or user-facing errors,
/// and it carries no memory text, provider response, or credential.
pub(crate) struct FencedAttemptToken {
    outbox_id: i64,
    life_id: String,
    memory_id: String,
    mutation_sequence: i64,
    action: MemoryVectorSyncAction,
    target_revision: Option<i64>,
    target_content_hash: Option<String>,
    generation_id: String,
    generation_authority_epoch: Option<i64>,
    descriptor_hash: String,
    dimension: usize,
    lease_owner: String,
    fence_epoch: i64,
    fenced_claim_epoch: i64,
    attempt_ordinal: i64,
}

#[allow(dead_code)]
impl FencedAttemptToken {
    /// The one-based ordinal of the reserved slot, equal to the persisted
    /// `attempt_count` at reservation time.
    pub(crate) fn attempt_ordinal(&self) -> i64 {
        self.attempt_ordinal
    }
    pub(crate) fn fenced_claim_epoch(&self) -> i64 {
        self.fenced_claim_epoch
    }
    pub(crate) fn outbox_id(&self) -> i64 {
        self.outbox_id
    }
    pub(crate) fn life_id(&self) -> &str {
        &self.life_id
    }
    pub(crate) fn memory_id(&self) -> &str {
        &self.memory_id
    }
    pub(crate) fn mutation_sequence(&self) -> i64 {
        self.mutation_sequence
    }
    pub(crate) fn action(&self) -> MemoryVectorSyncAction {
        self.action
    }
    pub(crate) fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub(crate) fn descriptor_hash(&self) -> &str {
        &self.descriptor_hash
    }
    pub(crate) fn dimension(&self) -> usize {
        self.dimension
    }
    pub(crate) fn lease_owner(&self) -> &str {
        &self.lease_owner
    }
    pub(crate) fn fence_epoch(&self) -> i64 {
        self.fence_epoch
    }
    pub(crate) fn target_revision(&self) -> Option<i64> {
        self.target_revision
    }
    pub(crate) fn target_content_hash(&self) -> Option<&str> {
        self.target_content_hash.as_deref()
    }

    /// A token is the complete claim identity after a slot is reserved. This
    /// private projection lets storage re-use the frozen claim-current checks
    /// without accepting a caller-supplied claim alongside the capability.
    fn claim_projection(&self) -> FencedVectorSyncClaim {
        FencedVectorSyncClaim {
            id: self.outbox_id,
            life_id: self.life_id.clone(),
            memory_id: self.memory_id.clone(),
            action: self.action,
            mutation_sequence: self.mutation_sequence,
            target_revision: self.target_revision,
            target_content_hash: self.target_content_hash.clone(),
            generation_id: self.generation_id.clone(),
            generation_authority_epoch: self.generation_authority_epoch,
            descriptor_hash: self.descriptor_hash.clone(),
            dimension: self.dimension,
            lease_owner: self.lease_owner.clone(),
            fence_epoch: self.fence_epoch,
            fenced_claim_epoch: self.fenced_claim_epoch,
        }
    }
}

/// The outcome of asking SQLite to reserve one Attempt slot.
///
/// It deliberately derives nothing: `Reserved` carries the token, and the token
/// must not gain `Debug`/`Clone` by way of this enum.
pub(crate) enum FencedAttemptReservation {
    /// The slot is durably reserved. A repeated reserve for the same claim epoch
    /// returns the same `attempt_ordinal` instead of consuming a new slot.
    Reserved(Box<FencedAttemptToken>),
    /// A stale owner, fence, mutation, target, generation, claim epoch, state, or
    /// migration boundary. Never an increment, and never a claim of corruption.
    LostLeaseOrSuperseded,
    /// The budget for this mutation is spent, so the row was converged to
    /// `blocked` instead of handing out a sixth slot.
    BudgetExhausted,
}

/// Outcome of durably recording the Delete external-call witness for a current
/// token. The witness is intentionally a distinct transition from reservation:
/// a token that loses currency before this point must not manufacture unknown
/// Delete evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FencedDeleteWitnessResult {
    Marked,
    LostLeaseOrSuperseded,
}

impl FencedAttemptReservation {
    #[cfg(test)]
    fn token(&self) -> Option<&FencedAttemptToken> {
        match self {
            Self::Reserved(token) => Some(token.as_ref()),
            Self::LostLeaseOrSuperseded | Self::BudgetExhausted => None,
        }
    }

    #[cfg(test)]
    fn ordinal(&self) -> Option<i64> {
        self.token().map(FencedAttemptToken::attempt_ordinal)
    }

    #[cfg(test)]
    fn is_lost(&self) -> bool {
        matches!(self, Self::LostLeaseOrSuperseded)
    }

    #[cfg(test)]
    fn is_budget_exhausted(&self) -> bool {
        matches!(self, Self::BudgetExhausted)
    }
}

pub(super) fn enqueue_in_transaction(
    transaction: &Transaction<'_>,
    life_id: &str,
    memory_id: &str,
    action: MemoryVectorSyncAction,
) -> Result<(), MemoryVectorSyncOutboxError> {
    validate_ids(life_id, memory_id)?;
    let memory: Option<(String, String, String, i64, String, Option<String>)> = transaction
        .query_row(
            "SELECT life_id, kind, status, revision, content, summary FROM memory_record WHERE id = ?1",
            params![memory_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        )
        .optional()
        .map_err(|_| outbox_error())?;
    match memory.as_ref().map(|row| row.0.as_str()) {
        None => {
            return Err(MemoryVectorSyncOutboxError::new(
                MemoryVectorSyncOutboxErrorCode::SyncJobNotFound,
            ));
        }
        Some(owner) if owner != life_id => {
            return Err(MemoryVectorSyncOutboxError::new(
                MemoryVectorSyncOutboxErrorCode::SyncJobLifeMismatch,
            ));
        }
        Some(_) => {}
    }
    let (target_revision, target_content_hash) = match action {
        MemoryVectorSyncAction::Upsert => {
            let (_, kind, status, revision, content, summary) =
                memory.as_ref().expect("checked memory");
            if status != "confirmed" {
                return Err(outbox_error());
            }
            let selected = summary
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or(content);
            if selected.trim().is_empty() {
                return Err(outbox_error());
            }
            if contains_prohibited_content(content)
                || summary.as_deref().is_some_and(contains_prohibited_content)
            {
                return Err(outbox_error());
            }
            (
                Some(*revision),
                Some(canonical_content_hash(
                    kind,
                    content,
                    summary.as_deref(),
                    selected,
                )),
            )
        }
        MemoryVectorSyncAction::Delete => (None, None),
    };
    let changed = transaction
        .execute(
            "UPDATE memory_vector_sync_mutation_clock
         SET last_sequence = last_sequence + 1
         WHERE singleton = 1 AND last_sequence < 9223372036854775807",
            [],
        )
        .map_err(|_| outbox_error())?;
    if changed != 1 {
        return Err(outbox_error());
    }
    let sequence: i64 = transaction
        .query_row(
            "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton = 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| outbox_error())?;
    // This one SQLite timestamp is shared by the supersede and the new outbox
    // mutation.  The enclosing transaction makes an unresolved old Late Delete
    // impossible to observe alongside the replacement mutation.
    let transaction_now = late_delete_resolution::authoritative_utc_millis_now_in(transaction)
        .map_err(|_| outbox_error())?;
    late_delete_resolution::supersede_for_new_mutation_in(
        transaction,
        life_id,
        memory_id,
        sequence,
        &transaction_now,
    )
    .map_err(|_| outbox_error())?;
    transaction
        .execute(
            "INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, mutation_sequence, target_revision, target_content_hash, migration_disposition, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, ?7, ?7)
         ON CONFLICT(life_id, memory_id) DO UPDATE SET
           desired_action = excluded.desired_action, state = 'pending', attempt_count = 0,
           fenced_claim_epoch = 0, last_marked_claim_epoch = 0,
           next_attempt_at = NULL, lease_owner = NULL, lease_expires_at = NULL,
           lease_fence_epoch = NULL, claimed_generation_id = NULL, claimed_generation_authority_epoch = NULL, last_send_disposition = NULL,
           migration_disposition = NULL, mutation_sequence = excluded.mutation_sequence,
           target_revision = excluded.target_revision, target_content_hash = excluded.target_content_hash,
           last_error_code = NULL, updated_at = excluded.updated_at",
            params![life_id, memory_id, action.as_str(), sequence, target_revision, target_content_hash, transaction_now],
        )
        .map_err(|_| outbox_error())?;
    Ok(())
}

fn canonical_content_hash(
    kind: &str,
    content: &str,
    summary: Option<&str>,
    selected: &str,
) -> String {
    let mut hasher = Sha256::new();
    for field in [
        b"memory-index-v1".as_slice(),
        kind.as_bytes(),
        selected.as_bytes(),
        content.as_bytes(),
        summary.unwrap_or_default().as_bytes(),
    ] {
        hasher.update((field.len() as u64).to_be_bytes());
        hasher.update(field);
    }
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Private capability returned only after the global runtime lease and the
/// event lease have both been acquired.  It deliberately has no constructor
/// and its debug output never contains memory text or provider data.
#[allow(dead_code)]
pub(crate) struct FencedVectorSyncClaim {
    id: i64,
    life_id: String,
    memory_id: String,
    action: MemoryVectorSyncAction,
    mutation_sequence: i64,
    target_revision: Option<i64>,
    target_content_hash: Option<String>,
    generation_id: String,
    generation_authority_epoch: Option<i64>,
    descriptor_hash: String,
    dimension: usize,
    lease_owner: String,
    fence_epoch: i64,
    /// The ordinary claim epoch this claim was granted, read back from the row
    /// after the claiming transaction incremented it. Callers never compute or
    /// advance it, and it is never exposed beyond the storage crate.
    fenced_claim_epoch: i64,
}

/// Internal-only classification of the persisted binding boundary.  It is
/// deliberately neither serialized nor exposed through the storage API: the
/// outbox row remains the authority for the binding lifecycle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenerationBindingPhase {
    Unbound,
    Ephemeral,
    Durable,
    MissingAfterAttempt,
    Invalid,
}

#[derive(Clone, Copy)]
struct GenerationBindingFacts<'a> {
    state: &'a str,
    attempt_count: i64,
    claimed_generation_id: Option<&'a str>,
    claimed_generation_authority_epoch: Option<i64>,
    lease_owner: Option<&'a str>,
    lease_fence_epoch: Option<i64>,
    lease_expires_at: Option<&'a str>,
}

/// The single authority for deciding whether a persisted generation binding
/// can be released.  A pre-attempt binding is ephemeral only while the whole
/// fenced processing claim is structurally present; expiry is intentionally
/// not part of this phase distinction because recovery decides that boundary.
fn generation_binding_phase(facts: GenerationBindingFacts<'_>) -> GenerationBindingPhase {
    let has_valid_generation = facts
        .claimed_generation_id
        .is_some_and(|generation_id| !generation_id.is_empty());
    // The frozen D9D2 building bridge intentionally predates the active
    // authority epoch, so its durable identity is `(generation_id, NULL)`.
    // Schema-17 ordinary execution remains exact-pair-only: the active claim
    // selector and token predicates require `Some(epoch >= 1)`, while their
    // legacy branch separately requires `state='building'`.  Keeping that
    // structural distinction here preserves frozen building no-replay tests
    // without allowing a historical NULL epoch to bind to an active generation.
    let paired_generation = has_valid_generation
        && facts
            .claimed_generation_authority_epoch
            .is_none_or(|epoch| epoch >= 1);
    if facts.attempt_count > 0 {
        return if paired_generation {
            GenerationBindingPhase::Durable
        } else if facts.claimed_generation_id.is_none() {
            GenerationBindingPhase::MissingAfterAttempt
        } else {
            GenerationBindingPhase::Invalid
        };
    }
    if facts.attempt_count != 0 {
        return GenerationBindingPhase::Invalid;
    }

    let has_no_lease = facts.lease_owner.is_none()
        && facts.lease_fence_epoch.is_none()
        && facts.lease_expires_at.is_none();
    if facts.claimed_generation_id.is_none() && facts.claimed_generation_authority_epoch.is_none() {
        return if has_no_lease
            && matches!(facts.state, "pending" | "retry_wait" | "blocked" | "failed")
        {
            GenerationBindingPhase::Unbound
        } else {
            GenerationBindingPhase::Invalid
        };
    }

    if facts.state == "processing"
        && paired_generation
        && facts
            .lease_owner
            .is_some_and(|owner| !owner.trim().is_empty())
        && facts.lease_fence_epoch.is_some_and(|fence| fence > 0)
        && facts
            .lease_expires_at
            .is_some_and(is_valid_utc_millis_timestamp)
    {
        GenerationBindingPhase::Ephemeral
    } else {
        GenerationBindingPhase::Invalid
    }
}

fn is_valid_utc_millis_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 24
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'.'
        || bytes[23] != b'Z'
    {
        return false;
    }
    let Some(year) = decimal(&bytes[0..4]) else {
        return false;
    };
    let Some(month) = decimal(&bytes[5..7]) else {
        return false;
    };
    let Some(day) = decimal(&bytes[8..10]) else {
        return false;
    };
    let Some(hour) = decimal(&bytes[11..13]) else {
        return false;
    };
    let Some(minute) = decimal(&bytes[14..16]) else {
        return false;
    };
    let Some(second) = decimal(&bytes[17..19]) else {
        return false;
    };
    decimal(&bytes[20..23]).is_some()
        && (1..=12).contains(&month)
        && (1..=days_in_month(year, month)).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

fn decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        if !byte.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add(u32::from(*byte - b'0'))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => 0,
    }
}

#[derive(Clone, Debug)]
struct GenerationBindingRow {
    id: i64,
    desired_action: String,
    mutation_sequence: i64,
    target_revision: Option<i64>,
    target_content_hash: Option<String>,
    state: String,
    attempt_count: i64,
    claimed_generation_id: Option<String>,
    claimed_generation_authority_epoch: Option<i64>,
    lease_owner: Option<String>,
    lease_fence_epoch: Option<i64>,
    lease_expires_at: Option<String>,
    last_send_disposition: Option<String>,
    last_error_code: Option<String>,
    fenced_claim_epoch: i64,
    last_marked_claim_epoch: i64,
}

/// The persisted Attempt-identity relationship between the two schema-14 claim
/// epoch columns and `attempt_count`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AttemptIdentityPhase {
    /// The current claim has not reserved its Attempt slot yet.
    ClaimUnmarked,
    /// The current claim already reserved its Attempt slot.
    ClaimMarked,
    /// No ordinary claim epoch has ever been granted. A schema-13 row migrated
    /// while `processing` lands here, and must never yield an Attempt token.
    NeverClaimed,
    /// A structurally impossible combination. The CHECK constraints make most of
    /// these unreachable through SQLite, so reaching one means the row is corrupt.
    Invalid,
}

/// Classifies the Attempt identity of one row. This is the single reader of the
/// two claim-epoch columns' relationship, so claim, reserve, and recovery cannot
/// disagree about what a row's epochs mean.
fn attempt_identity_phase(
    attempt_count: i64,
    fenced_claim_epoch: i64,
    last_marked_claim_epoch: i64,
) -> AttemptIdentityPhase {
    if attempt_count < 0 || fenced_claim_epoch < 0 || last_marked_claim_epoch < 0 {
        return AttemptIdentityPhase::Invalid;
    }
    if last_marked_claim_epoch > fenced_claim_epoch {
        return AttemptIdentityPhase::Invalid;
    }
    if last_marked_claim_epoch > 0 && attempt_count <= 0 {
        return AttemptIdentityPhase::Invalid;
    }
    // A count beyond the budget can only come from outside the single authoritative
    // reserve path (or a schema-13 row whose legacy worker incremented without a
    // budget). It is never runnable and never manually retryable.
    if attempt_count > MAX_VECTOR_SYNC_ATTEMPTS {
        return AttemptIdentityPhase::Invalid;
    }
    if fenced_claim_epoch == 0 {
        // A never-claimed row cannot have reserved an Attempt through the fenced
        // path, so a positive attempt_count here is legacy-only evidence.
        return AttemptIdentityPhase::NeverClaimed;
    }
    if last_marked_claim_epoch == fenced_claim_epoch {
        AttemptIdentityPhase::ClaimMarked
    } else {
        AttemptIdentityPhase::ClaimUnmarked
    }
}

impl GenerationBindingRow {
    fn facts(&self) -> GenerationBindingFacts<'_> {
        GenerationBindingFacts {
            state: &self.state,
            attempt_count: self.attempt_count,
            claimed_generation_id: self.claimed_generation_id.as_deref(),
            claimed_generation_authority_epoch: self.claimed_generation_authority_epoch,
            lease_owner: self.lease_owner.as_deref(),
            lease_fence_epoch: self.lease_fence_epoch,
            lease_expires_at: self.lease_expires_at.as_deref(),
        }
    }

    fn phase(&self) -> GenerationBindingPhase {
        generation_binding_phase(self.facts())
    }

    fn attempt_identity_phase(&self) -> AttemptIdentityPhase {
        attempt_identity_phase(
            self.attempt_count,
            self.fenced_claim_epoch,
            self.last_marked_claim_epoch,
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InvariantBlockOutcome {
    Applied,
    NotInvariant,
    Superseded,
}

enum FencedBindingCurrent {
    Current(Box<GenerationBindingRow>),
    NotCurrent,
}

struct ClaimCandidate {
    id: i64,
    attempt_count: i64,
    claimed_generation_id: Option<String>,
    claimed_generation_authority_epoch: Option<i64>,
    state: String,
    lease_owner: Option<String>,
    lease_fence_epoch: Option<i64>,
    lease_expires_at: Option<String>,
    fenced_claim_epoch: i64,
    last_marked_claim_epoch: i64,
}

fn claim_candidate_from_row(row: &Row<'_>) -> rusqlite::Result<ClaimCandidate> {
    Ok(ClaimCandidate {
        id: row.get(0)?,
        attempt_count: row.get(1)?,
        claimed_generation_id: row.get(2)?,
        claimed_generation_authority_epoch: row.get(3)?,
        state: row.get(4)?,
        lease_owner: row.get(5)?,
        lease_fence_epoch: row.get(6)?,
        lease_expires_at: row.get(7)?,
        fenced_claim_epoch: row.get(8)?,
        last_marked_claim_epoch: row.get(9)?,
    })
}

/// Error codes that already describe a permanent, stable outcome. When the budget
/// runs out, such a code is more specific than `MAX_ATTEMPTS` and is preserved.
const PERMANENT_ERROR_CODES: &[&str] = &[
    "PROVIDER_RESULT_UNKNOWN",
    "AUTHENTICATION_FAILED",
    "INVALID_REQUEST",
    "INVALID_PROVIDER_RESPONSE",
    "EMBEDDING_DIMENSION_MISMATCH",
    "EMBEDDING_INVALID_VECTOR",
    "LANCE_PERMANENT",
    "INTERNAL_INVARIANT",
    "MAX_ATTEMPTS",
    "VECTOR_TARGET_BINDING_MISSING",
];

impl std::fmt::Debug for FencedVectorSyncClaim {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FencedVectorSyncClaim")
            .field("id", &self.id)
            .field("action", &self.action)
            .field("mutation_sequence", &self.mutation_sequence)
            .field("has_target", &self.target_revision.is_some())
            .field("generation_id_len", &self.generation_id.len())
            .field("dimension", &self.dimension)
            .field("fence_epoch", &self.fence_epoch)
            .field("fenced_claim_epoch", &self.fenced_claim_epoch)
            .finish()
    }
}

#[allow(dead_code)]
impl FencedVectorSyncClaim {
    pub(crate) fn id(&self) -> i64 {
        self.id
    }
    pub(crate) fn mutation_sequence(&self) -> i64 {
        self.mutation_sequence
    }
    pub(crate) fn lease_owner(&self) -> &str {
        &self.lease_owner
    }
    pub(crate) fn fence_epoch(&self) -> i64 {
        self.fence_epoch
    }
    pub(crate) fn fenced_claim_epoch(&self) -> i64 {
        self.fenced_claim_epoch
    }
    pub(crate) fn action(&self) -> MemoryVectorSyncAction {
        self.action
    }
    pub(crate) fn life_id(&self) -> &str {
        &self.life_id
    }
    pub(crate) fn memory_id(&self) -> &str {
        &self.memory_id
    }
    pub(crate) fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub(crate) fn target_revision(&self) -> Option<i64> {
        self.target_revision
    }
    pub(crate) fn target_content_hash(&self) -> Option<&str> {
        self.target_content_hash.as_deref()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum FencedFinalizeResult {
    Applied,
    LostLeaseOrSuperseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FencedFailureDecision {
    RetryAfter { delay_millis: u64 },
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FencedFailureFinalizeResult {
    RetryScheduled { next_attempt_at_millis: i64 },
    Blocked,
    LostLeaseOrSuperseded,
}

type FencedFailureFinalizeSnapshot = (
    String,
    Option<String>,
    i64,
    Option<String>,
    Option<String>,
    Option<i64>,
    Option<String>,
    Option<String>,
    i64,
    i64,
    Option<String>,
);

/// Test-only compatibility result for assertions that predate ATT-I3 token
/// ownership. Production workers receive [`FencedAttemptToken`] directly.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FencedAttemptStartResult {
    Started { attempt_count: u32 },
    LostLeaseOrSuperseded,
}

// Keep older fenced-test assertions source-compatible while callers migrate to
// the count-bearing result. Production callers use an explicit match.
#[cfg(test)]
impl std::ops::Not for FencedAttemptStartResult {
    type Output = bool;

    fn not(self) -> Self::Output {
        matches!(self, Self::LostLeaseOrSuperseded)
    }
}

/// Sealed authority proof representing a unique `building` candidate in SQLite.
///
/// It deliberately has no `Clone`, no `Copy`, no `Debug`, no `Serialize`, no `Deserialize`,
/// and no raw scalar getters to ensure the caller cannot extract generation scalars or
/// bypass authority rechecks.
pub(crate) struct ExistingBuildingGenerationAuthority {
    generation_id: String,
    descriptor_hash: String,
    dimension: usize,
    authority_epoch: i64,
}

/// Opaque proof of the one active generation selected by the Schema-17
/// singleton authority row.  It deliberately remains storage-owned: callers
/// can validate and consume it, but cannot manufacture it from scalars.
pub(crate) struct ActiveGenerationAuthority {
    generation_id: String,
    descriptor_hash: String,
    dimension: usize,
    authority_epoch: i64,
    embedding_profile_id: String,
}

impl ActiveGenerationAuthority {
    pub(crate) fn bound_embedding_profile_id(&self) -> &str {
        &self.embedding_profile_id
    }

    pub(crate) fn verify_descriptor_and_dimension(
        &self,
        descriptor_hash: &str,
        dimension: usize,
    ) -> Result<(), ExistingGenerationBindingError> {
        if self.descriptor_hash != descriptor_hash || self.dimension != dimension {
            return Err(ExistingGenerationBindingError::generation_binding_mismatch());
        }
        Ok(())
    }

    /// Rechecks every persisted active-authority fact immediately before the
    /// context is sealed for execution.  This is intentionally a read-only
    /// capability transition; B never changes the pointer or lifecycle state.
    pub(crate) fn verify_current_and_seal(
        self,
        storage: &StorageService,
    ) -> Result<(VectorGenerationContext, i64), ExistingGenerationBindingError> {
        let state = storage
            .state()
            .map_err(|_| ExistingGenerationBindingError::generation_binding_stale())?;
        let current: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(
                SELECT 1
                FROM memory_vector_generation_authority a
                JOIN memory_vector_generation g ON g.generation_id=a.active_generation_id
                JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id
                JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id
                WHERE a.singleton=1 AND a.active_generation_id=?1
                  AND g.descriptor_hash=?2 AND g.dimension=?3
                  AND g.state='active' AND g.authority_epoch=?4
                  AND b.descriptor_version=?5 AND b.embedding_profile_id=?6
                  AND w.state='ready'
            )",
                params![
                    self.generation_id,
                    self.descriptor_hash,
                    self.dimension as i64,
                    self.authority_epoch,
                    crate::memory::existing_generation_binding::D9D2_GENERATION_DESCRIPTOR_VERSION,
                    self.embedding_profile_id
                ],
                |row| row.get(0),
            )
            .map_err(|_| ExistingGenerationBindingError::generation_binding_stale())?;
        if !current {
            return Err(ExistingGenerationBindingError::generation_binding_stale());
        }
        let generation_id = VectorGenerationId::parse(&self.generation_id)
            .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())?;
        let context =
            VectorGenerationContext::new(generation_id, self.descriptor_hash, self.dimension)
                .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())?;
        Ok((context, self.authority_epoch))
    }
}

impl ExistingBuildingGenerationAuthority {
    /// Verifies that the expected descriptor hash and expected dimension match the candidate authority.
    pub(crate) fn verify_descriptor_and_dimension(
        &self,
        expected_descriptor_hash: &str,
        expected_dimension: usize,
    ) -> Result<(), ExistingGenerationBindingError> {
        if self.descriptor_hash != expected_descriptor_hash || self.dimension != expected_dimension
        {
            return Err(ExistingGenerationBindingError::generation_binding_mismatch());
        }
        Ok(())
    }

    /// Performs the exact authority recheck against authoritative SQLite storage
    /// and produces the sealed VectorGenerationContext only on exact match.
    pub(crate) fn verify_current_and_seal(
        self,
        storage: &StorageService,
    ) -> Result<VectorGenerationContext, ExistingGenerationBindingError> {
        let state = storage
            .state()
            .map_err(|_| ExistingGenerationBindingError::generation_binding_stale())?;

        let matches: bool = state
            .connection
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM memory_vector_generation
                    WHERE generation_id = ?1
                      AND descriptor_hash = ?2
                      AND dimension = ?3
                      AND state = 'building'
                      AND authority_epoch = ?4
                )",
                params![
                    self.generation_id,
                    self.descriptor_hash,
                    self.dimension as i64,
                    self.authority_epoch,
                ],
                |row| row.get(0),
            )
            .map_err(|_| ExistingGenerationBindingError::generation_binding_stale())?;

        if !matches {
            return Err(ExistingGenerationBindingError::generation_binding_stale());
        }

        let generation_id = VectorGenerationId::parse(&self.generation_id)
            .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())?;

        VectorGenerationContext::new(generation_id, self.descriptor_hash, self.dimension)
            .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())
    }
}

#[allow(dead_code)]
impl StorageService {
    /// Loads exactly the active generation selected by the singleton pointer.
    /// Every join is exact and mandatory, so malformed, historical, or
    /// non-ready state fails closed before provider resolution or store access.
    pub(crate) fn load_active_generation_authority(
        &self,
    ) -> Result<ActiveGenerationAuthority, ExistingGenerationBindingError> {
        let state = self
            .state()
            .map_err(|_| ExistingGenerationBindingError::no_existing_generation())?;
        let row: Option<(String, String, i64, String, i64, String)> = state.connection.query_row(
            "SELECT g.generation_id,g.descriptor_hash,g.dimension,g.state,g.authority_epoch,b.embedding_profile_id
             FROM memory_vector_generation_authority a
             JOIN memory_vector_generation g ON g.generation_id=a.active_generation_id
             JOIN memory_vector_generation_binding b ON b.generation_id=g.generation_id
             JOIN memory_vector_generation_store_witness w ON w.generation_id=g.generation_id
             WHERE a.singleton=1 AND a.active_generation_id IS NOT NULL
               AND g.state='active' AND g.authority_epoch>=1
               AND b.descriptor_version=?1 AND trim(b.embedding_profile_id)<>''
               AND w.state='ready'",
            [crate::memory::existing_generation_binding::D9D2_GENERATION_DESCRIPTOR_VERSION],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).optional().map_err(|_| ExistingGenerationBindingError::no_existing_generation())?;
        let Some((
            generation_id,
            descriptor_hash,
            dimension,
            generation_state,
            authority_epoch,
            embedding_profile_id,
        )) = row
        else {
            return Err(ExistingGenerationBindingError::no_existing_generation());
        };
        if generation_state != "active"
            || authority_epoch < 1
            || dimension <= 0
            || dimension > crate::embedding::MAX_VECTOR_DIMENSION as i64
            || VectorGenerationId::parse(&generation_id).is_err()
            || descriptor_hash.trim().is_empty()
            || embedding_profile_id.trim().is_empty()
        {
            return Err(ExistingGenerationBindingError::invalid_generation_metadata());
        }
        Ok(ActiveGenerationAuthority {
            generation_id,
            descriptor_hash,
            dimension: dimension as usize,
            authority_epoch,
            embedding_profile_id,
        })
    }

    /// Loads the unique building generation candidate from SQLite generation authority.
    ///
    /// Evaluates `SELECT ... FROM memory_vector_generation WHERE state = 'building' LIMIT 2`:
    /// - 0 rows -> `D9D2_NO_EXISTING_GENERATION`
    /// - 1 row -> validates metadata -> `ExistingBuildingGenerationAuthority`
    /// - 2 rows -> `D9D2_AMBIGUOUS_EXISTING_GENERATION`
    pub(crate) fn load_existing_building_generation_candidate(
        &self,
    ) -> Result<ExistingBuildingGenerationAuthority, ExistingGenerationBindingError> {
        let state = self
            .state()
            .map_err(|_| ExistingGenerationBindingError::no_existing_generation())?;

        let mut stmt = state
            .connection
            .prepare(
                "SELECT generation_id, descriptor_hash, dimension, state, authority_epoch
                 FROM memory_vector_generation
                 WHERE state = 'building'
                 LIMIT 2",
            )
            .map_err(|_| ExistingGenerationBindingError::no_existing_generation())?;

        let mut rows = stmt
            .query([])
            .map_err(|_| ExistingGenerationBindingError::no_existing_generation())?;

        let first = rows
            .next()
            .map_err(|_| ExistingGenerationBindingError::no_existing_generation())?;

        let Some(first_row) = first else {
            return Err(ExistingGenerationBindingError::no_existing_generation());
        };

        let gen_id_raw: String = first_row
            .get(0)
            .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())?;
        let descriptor_hash: String = first_row
            .get(1)
            .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())?;
        let dimension_raw: i64 = first_row
            .get(2)
            .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())?;
        let state_raw: String = first_row
            .get(3)
            .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())?;
        let authority_epoch: i64 = first_row
            .get(4)
            .map_err(|_| ExistingGenerationBindingError::invalid_generation_metadata())?;

        // Check if there is an ambiguous 2nd row
        let second = rows
            .next()
            .map_err(|_| ExistingGenerationBindingError::no_existing_generation())?;

        if second.is_some() {
            return Err(ExistingGenerationBindingError::ambiguous_existing_generation());
        }

        // Validate metadata of candidate row
        if state_raw != "building" {
            return Err(ExistingGenerationBindingError::invalid_generation_metadata());
        }
        if authority_epoch <= 0 {
            return Err(ExistingGenerationBindingError::invalid_generation_metadata());
        }
        if dimension_raw <= 0 || dimension_raw > crate::embedding::MAX_VECTOR_DIMENSION as i64 {
            return Err(ExistingGenerationBindingError::invalid_generation_metadata());
        }
        if descriptor_hash.len() != 64
            || !descriptor_hash
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        {
            return Err(ExistingGenerationBindingError::invalid_generation_metadata());
        }
        if VectorGenerationId::parse(&gen_id_raw).is_err() {
            return Err(ExistingGenerationBindingError::invalid_generation_metadata());
        }

        Ok(ExistingBuildingGenerationAuthority {
            generation_id: gen_id_raw,
            descriptor_hash,
            dimension: dimension_raw as usize,
            authority_epoch,
        })
    }

    /// D-9D1 creates only explicit, non-active generations.  Activation and
    /// rebuild orchestration remain D-9D3 responsibilities.
    pub(crate) fn register_building_vector_generation(
        &self,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
    ) -> Result<(), crate::storage::StorageError> {
        if generation_id.is_empty() || descriptor_hash.is_empty() || dimension == 0 {
            return Err(single_event_error());
        }
        let state = self.state()?;
        state.connection.execute(
            "INSERT INTO memory_vector_generation (generation_id, descriptor_hash, dimension, state, authority_epoch)
             VALUES (?1, ?2, ?3, 'building', 1)
             ON CONFLICT(generation_id) DO NOTHING",
            params![generation_id, descriptor_hash, dimension as i64],
        ).map_err(|_| single_event_error())?;
        let existing: Option<(String, i64, String)> = state
            .connection
            .query_row(
                "SELECT descriptor_hash, dimension, state FROM memory_vector_generation WHERE generation_id=?1",
                params![generation_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()
            .map_err(|_| single_event_error())?;
        let Some((existing_descriptor, existing_dimension, existing_state)) = existing else {
            return Err(single_event_error());
        };
        if existing_descriptor != descriptor_hash {
            return Err(crate::storage::StorageError::new(
                "GENERATION_DESCRIPTOR_MISMATCH",
                "The vector generation descriptor does not match.",
                false,
            ));
        }
        if existing_dimension != dimension as i64 {
            return Err(crate::storage::StorageError::new(
                "GENERATION_DIMENSION_MISMATCH",
                "The vector generation dimension does not match.",
                false,
            ));
        }
        if existing_state != "building" {
            return Err(crate::storage::StorageError::new(
                "GENERATION_STATE_CONFLICT",
                "The vector generation cannot be registered in its current state.",
                false,
            ));
        }
        Ok(())
    }

    pub(crate) fn claim_one_fenced_vector_sync(
        &self,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
        lease_owner: &str,
    ) -> Result<Option<FencedVectorSyncClaim>, crate::storage::StorageError> {
        self.claim_one_fenced_vector_sync_with_retry_cutoff(
            generation_id,
            descriptor_hash,
            dimension,
            lease_owner,
            None,
        )
    }

    pub(crate) fn claim_one_fenced_vector_sync_with_retry_cutoff(
        &self,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
        lease_owner: &str,
        retry_cutoff_millis: Option<i64>,
    ) -> Result<Option<FencedVectorSyncClaim>, crate::storage::StorageError> {
        self.claim_one_fenced_vector_sync_with_authority_epoch(
            generation_id,
            descriptor_hash,
            dimension,
            lease_owner,
            retry_cutoff_millis,
            None,
        )
    }

    /// Schema-17 ordinary claim path. The active resolver is the only
    /// production caller; the epoch is persisted together with the generation.
    pub(crate) fn claim_one_active_fenced_vector_sync_with_retry_cutoff(
        &self,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
        authority_epoch: i64,
        lease_owner: &str,
        retry_cutoff_millis: Option<i64>,
    ) -> Result<Option<FencedVectorSyncClaim>, crate::storage::StorageError> {
        self.claim_one_fenced_vector_sync_with_authority_epoch(
            generation_id,
            descriptor_hash,
            dimension,
            lease_owner,
            retry_cutoff_millis,
            Some(authority_epoch),
        )
    }

    fn claim_one_fenced_vector_sync_with_authority_epoch(
        &self,
        generation_id: &str,
        descriptor_hash: &str,
        dimension: usize,
        lease_owner: &str,
        retry_cutoff_millis: Option<i64>,
        authority_epoch: Option<i64>,
    ) -> Result<Option<FencedVectorSyncClaim>, crate::storage::StorageError> {
        if generation_id.is_empty()
            || descriptor_hash.is_empty()
            || dimension == 0
            || lease_owner.is_empty()
            || lease_owner.len() > 128
            || retry_cutoff_millis.is_some_and(|value| value < 0)
            || authority_epoch.is_some_and(|epoch| epoch < 1)
        {
            return Err(single_event_error());
        }
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let fence_epoch = acquire_runtime_lease(&tx, lease_owner)?;
        // `recover_expired_fenced_processing_in` begins by repairing
        // structurally invalid rows before candidate selection. They must not
        // remain ordinary pending/retry work merely because the candidate
        // predicate excludes them.
        // A malformed post-012 upsert is fail-closed without materializing its
        // current memory body.  This transition releases a generation only
        // after the shared phase classifier proves it was Ephemeral.
        quarantine_malformed_target_bindings_in(&tx)?;
        recover_expired_fenced_processing_in(&tx, retry_cutoff_millis)?;
        // Runs after recovery, so a row that recovery just returned to `pending`
        // with a spent budget converges in this same transaction instead of
        // surviving as ordinary work until the next claim.
        converge_exhausted_attempt_budget_in(&tx)?;
        let generation_ok: Option<i64> = match authority_epoch {
            Some(epoch) => tx.query_row(
                "SELECT 1 FROM memory_vector_generation_authority a JOIN memory_vector_generation g ON g.generation_id=a.active_generation_id
                 WHERE a.singleton=1 AND a.active_generation_id=?1 AND g.descriptor_hash=?2 AND g.dimension=?3
                   AND g.state='active' AND g.authority_epoch=?4",
                params![generation_id, descriptor_hash, dimension as i64, epoch], |row| row.get(0),
            ).optional().map_err(|_| single_event_error())?,
            None => tx.query_row(
                "SELECT 1 FROM memory_vector_generation WHERE generation_id=?1 AND descriptor_hash=?2 AND dimension=?3 AND state='building'",
                params![generation_id, descriptor_hash, dimension as i64], |row| row.get(0),
            ).optional().map_err(|_| single_event_error())?,
        };
        if generation_ok.is_none() {
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(None);
        }
        let candidate: Option<ClaimCandidate> = match retry_cutoff_millis {
            Some(retry_cutoff_millis) => tx
                .query_row(
                    &format!(
                    "SELECT id, attempt_count, claimed_generation_id, claimed_generation_authority_epoch, state,
                            lease_owner, lease_fence_epoch, lease_expires_at,
                            fenced_claim_epoch, last_marked_claim_epoch
                     FROM memory_vector_sync_outbox WHERE migration_disposition IS NULL AND
                      ((desired_action='upsert' AND target_revision IS NOT NULL AND target_content_hash IS NOT NULL)
                       OR (desired_action='delete' AND target_revision IS NULL AND target_content_hash IS NULL)) AND
                      (state='pending' OR (state='retry_wait' AND next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%fZ', ?1 / 1000.0, 'unixepoch')))
                      AND attempt_count < {MAX_VECTOR_SYNC_ATTEMPTS}
                      AND ((attempt_count=0 AND claimed_generation_id IS NULL AND claimed_generation_authority_epoch IS NULL)
                           OR (attempt_count>0 AND claimed_generation_id=?2
                               AND ((?3 IS NULL AND claimed_generation_authority_epoch IS NULL)
                                    OR claimed_generation_authority_epoch=?3)))
                       AND NOT (desired_action='upsert' AND
                                (COALESCE(last_send_disposition, '')='possibly_sent' OR COALESCE(last_error_code, '')='PROVIDER_RESULT_UNKNOWN'))
                       AND NOT ({DELETE_UNKNOWN_EVIDENCE_SQL})
                    ORDER BY mutation_sequence ASC, id ASC LIMIT 1"
                    ),
                    params![retry_cutoff_millis, generation_id, authority_epoch],
                    claim_candidate_from_row,
                )
                .optional()
                .map_err(|_| single_event_error())?,
            None => tx
                .query_row(
                    &format!(
                    "SELECT id, attempt_count, claimed_generation_id, claimed_generation_authority_epoch, state,
                            lease_owner, lease_fence_epoch, lease_expires_at,
                            fenced_claim_epoch, last_marked_claim_epoch
                     FROM memory_vector_sync_outbox WHERE migration_disposition IS NULL AND
                      ((desired_action='upsert' AND target_revision IS NOT NULL AND target_content_hash IS NOT NULL)
                       OR (desired_action='delete' AND target_revision IS NULL AND target_content_hash IS NULL)) AND
                      (state='pending' OR (state='retry_wait' AND next_attempt_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now')))
                      AND attempt_count < {MAX_VECTOR_SYNC_ATTEMPTS}
                      AND ((attempt_count=0 AND claimed_generation_id IS NULL AND claimed_generation_authority_epoch IS NULL)
                           OR (attempt_count>0 AND claimed_generation_id=?1
                               AND ((?2 IS NULL AND claimed_generation_authority_epoch IS NULL)
                                    OR claimed_generation_authority_epoch=?2)))
                       AND NOT (desired_action='upsert' AND
                                (COALESCE(last_send_disposition, '')='possibly_sent' OR COALESCE(last_error_code, '')='PROVIDER_RESULT_UNKNOWN'))
                       AND NOT ({DELETE_UNKNOWN_EVIDENCE_SQL})
                    ORDER BY mutation_sequence ASC, id ASC LIMIT 1"
                    ),
                    params![generation_id, authority_epoch],
                    claim_candidate_from_row,
                )
                .optional()
                .map_err(|_| single_event_error())?,
        };
        let Some(candidate) = candidate else {
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(None);
        };
        // The two claim-epoch columns are validated before any lease is taken, so a
        // structurally impossible Attempt identity can never be granted a claim.
        if matches!(
            attempt_identity_phase(
                candidate.attempt_count,
                candidate.fenced_claim_epoch,
                candidate.last_marked_claim_epoch,
            ),
            AttemptIdentityPhase::Invalid
        ) {
            block_claim_candidate_identity_in(&tx, &candidate)?;
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(None);
        }
        // Fail closed rather than wrapping, saturating, or going negative. A row
        // that can no longer take a distinct claim epoch can never again prove
        // which claim reserved an Attempt, so it must not run.
        if candidate.fenced_claim_epoch == i64::MAX {
            block_claim_candidate_identity_in(&tx, &candidate)?;
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(None);
        }
        let changed = match generation_binding_phase(GenerationBindingFacts {
            state: &candidate.state,
            attempt_count: candidate.attempt_count,
            claimed_generation_id: candidate.claimed_generation_id.as_deref(),
            claimed_generation_authority_epoch: candidate.claimed_generation_authority_epoch,
            lease_owner: candidate.lease_owner.as_deref(),
            lease_fence_epoch: candidate.lease_fence_epoch,
            lease_expires_at: candidate.lease_expires_at.as_deref(),
        }) {
            // Every successful claim cycle takes a new fenced_claim_epoch, even
            // when the owner, runtime fence, mutation, and generation are all
            // reused. last_marked_claim_epoch is deliberately never written here:
            // only a reservation may advance it.
            GenerationBindingPhase::Unbound => tx.execute(
                "UPDATE memory_vector_sync_outbox SET state='processing',
                 lease_owner=?2, lease_fence_epoch=?3, claimed_generation_id=?4, claimed_generation_authority_epoch=?5,
                 fenced_claim_epoch=fenced_claim_epoch+1,
                 lease_expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+120 seconds'), next_attempt_at=NULL,
                 last_send_disposition=NULL,
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE id=?1 AND migration_disposition IS NULL AND state IN ('pending','retry_wait')
                   AND attempt_count=0 AND claimed_generation_id IS NULL AND claimed_generation_authority_epoch IS NULL
                   AND fenced_claim_epoch=?6 AND last_marked_claim_epoch=?7
                   AND fenced_claim_epoch < 9223372036854775807",
                params![
                    candidate.id,
                    lease_owner,
                    fence_epoch,
                    generation_id,
                    authority_epoch,
                    candidate.fenced_claim_epoch,
                    candidate.last_marked_claim_epoch,
                ],
            ),
            GenerationBindingPhase::Durable
                if candidate.claimed_generation_id.as_deref() == Some(generation_id)
                    && candidate.claimed_generation_authority_epoch == authority_epoch =>
            {
                tx.execute(
                    &format!(
                    "UPDATE memory_vector_sync_outbox SET state='processing',
                     lease_owner=?2, lease_fence_epoch=?3,
                     fenced_claim_epoch=fenced_claim_epoch+1,
                     lease_expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+120 seconds'), next_attempt_at=NULL,
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE id=?1 AND migration_disposition IS NULL AND state IN ('pending','retry_wait')
                       AND attempt_count>0 AND attempt_count < {MAX_VECTOR_SYNC_ATTEMPTS}
                       AND claimed_generation_id=?4 AND claimed_generation_authority_epoch IS ?5
                       AND fenced_claim_epoch=?6 AND last_marked_claim_epoch=?7
                       AND fenced_claim_epoch < 9223372036854775807"
                    ),
                    params![
                        candidate.id,
                        lease_owner,
                        fence_epoch,
                        generation_id,
                        authority_epoch,
                        candidate.fenced_claim_epoch,
                        candidate.last_marked_claim_epoch,
                    ],
                )
            }
            GenerationBindingPhase::Ephemeral
            | GenerationBindingPhase::MissingAfterAttempt
            | GenerationBindingPhase::Invalid
            | GenerationBindingPhase::Durable => {
                tx.commit().map_err(|_| single_event_error())?;
                return Ok(None);
            }
        }
        .map_err(|_| single_event_error())?;
        if changed != 1 {
            return Err(single_event_error());
        }
        // The claim carries the epoch SQLite just assigned, read back from the row
        // inside this same transaction. Callers never compute or advance it.
        let claim = tx.query_row(
            "SELECT id, life_id, memory_id, desired_action, mutation_sequence, target_revision, target_content_hash,
                    claimed_generation_id, claimed_generation_authority_epoch, lease_owner, lease_fence_epoch, fenced_claim_epoch
             FROM memory_vector_sync_outbox WHERE id=?1", params![candidate.id], |row| {
                fenced_claim_from_row(row, descriptor_hash, dimension)
             },
        ).map_err(|_| single_event_error())?;
        tx.commit().map_err(|_| single_event_error())?;
        Ok(Some(claim))
    }

    /// Reads authority only after a structurally valid upsert claim exists.
    /// A mismatch is returned as `None`, making stale data a safe no-write.
    pub(crate) fn read_fenced_vector_document(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<Option<String>, crate::storage::StorageError> {
        if claim.action != MemoryVectorSyncAction::Upsert {
            return Ok(None);
        }
        let state = self.state()?;
        let row: Option<(String, String, i64, String, Option<String>, i64)> = state.connection.query_row(
            "SELECT kind, status, revision, content, summary, is_sensitive FROM memory_record WHERE id=?1 AND life_id=?2",
            params![claim.memory_id, claim.life_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
        ).optional().map_err(|_| single_event_error())?;
        let Some((kind, status, revision, content, summary, sensitive)) = row else {
            return Ok(None);
        };
        if status != "confirmed" || sensitive != 0 || Some(revision) != claim.target_revision {
            return Ok(None);
        }
        if contains_prohibited_content(&content)
            || summary.as_deref().is_some_and(contains_prohibited_content)
        {
            return Ok(None);
        }
        let selected = summary
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or(&content);
        if selected.trim().is_empty()
            || Some(canonical_content_hash(&kind, &content, summary.as_deref(), selected).as_str())
                != claim.target_content_hash()
        {
            return Ok(None);
        }
        Ok(Some(selected.to_owned()))
    }

    /// A second, short authority check immediately before external I/O. It
    /// cannot make SQLite and LanceDB one transaction, but it prevents a known
    /// superseded or expired claim from initiating a provider or vector
    /// operation. This guard deliberately does not renew either lease: only a
    /// new claim may establish a fresh bounded lease interval.
    pub(crate) fn fenced_vector_claim_is_current(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<bool, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let current = matches!(
            inspect_fenced_generation_binding_in(&tx, claim)?,
            FencedBindingCurrent::Current(_)
        );
        tx.commit().map_err(|_| single_event_error())?;
        Ok(current)
    }

    /// The single authoritative Attempt reservation. It is the only code in the
    /// repository that may advance `attempt_count` or `last_marked_claim_epoch`.
    ///
    /// Reserving is idempotent per claim epoch: the first reserve for a claim
    /// consumes one budget slot, and every later reserve for that same claim epoch
    /// returns the identical ordinal and an equivalent token without consuming
    /// another slot. That is what makes a lost commit result safe to retry.
    pub(crate) fn reserve_fenced_attempt(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<FencedAttemptReservation, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let reservation = reserve_fenced_attempt_in(&tx, claim)?;
        tx.commit().map_err(|_| single_event_error())?;
        // The reservation is durable at this point. The test seam below models a
        // caller that never learns that, so the retry path can be proven.
        #[cfg(test)]
        if take_post_commit_reserve_fault_for_test() {
            return Err(single_event_error());
        }
        Ok(reservation)
    }

    /// Transitional compatibility for non-worker tests only. ATT-I3 workers
    /// must carry the returned [`FencedAttemptToken`] through their external
    /// Attempt and never call this count-only wrapper. It still delegates to the
    /// one authoritative reserve implementation, so it cannot create a second
    /// increment path or manufacture a bare ordinal.
    #[cfg(test)]
    pub(crate) fn mark_fenced_attempt_started(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<FencedAttemptStartResult, crate::storage::StorageError> {
        match self.reserve_fenced_attempt(claim)? {
            FencedAttemptReservation::Reserved(token) => {
                let attempt_count =
                    u32::try_from(token.attempt_ordinal).map_err(|_| single_event_error())?;
                Ok(FencedAttemptStartResult::Started { attempt_count })
            }
            // A spent budget is not a distinguishable outcome in the pre-ATT-I3
            // shape, and it is not a new Attempt, so it fails closed exactly like a
            // superseded claim.
            FencedAttemptReservation::LostLeaseOrSuperseded
            | FencedAttemptReservation::BudgetExhausted => {
                Ok(FencedAttemptStartResult::LostLeaseOrSuperseded)
            }
        }
    }

    /// Read-only currency check for a reservation. The token is the sole
    /// capability argument: callers cannot pair a valid token with a different
    /// claim or reconstruct one from a row read.
    pub(crate) fn validate_fenced_attempt_token_current(
        &self,
        token: &FencedAttemptToken,
    ) -> Result<bool, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| single_event_error())?;
        let claim = token.claim_projection();
        let current = fenced_attempt_token_current_in(&tx, &claim, token)?;
        tx.commit().map_err(|_| single_event_error())?;
        Ok(current)
    }

    /// Persists the Delete external-call witness after the first Token Guard but
    /// before Lance is invoked. The complete token CAS prevents an old Attempt
    /// from marking a newer mutation or claim epoch as unproven.
    pub(crate) fn mark_fenced_delete_send_witness(
        &self,
        token: &FencedAttemptToken,
    ) -> Result<FencedDeleteWitnessResult, crate::storage::StorageError> {
        if token.action != MemoryVectorSyncAction::Delete {
            return Ok(FencedDeleteWitnessResult::LostLeaseOrSuperseded);
        }
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let current_now = authoritative_utc_millis_now_in(&tx)?;
        let changed = tx
            .execute(
                &format!(
                    "UPDATE memory_vector_sync_outbox
                         SET last_send_disposition='possibly_sent',
                         delete_witness_at=CASE WHEN delete_witness_at IS NULL THEN :delete_witness_at ELSE delete_witness_at END,
                         updated_at=:delete_witness_at
                     WHERE {FENCED_ATTEMPT_TOKEN_FINALIZE_IDENTITY}"
                ),
                rusqlite::named_params! {
                    ":current_now": current_now.as_str(),
                    ":delete_witness_at": current_now.as_str(),
                    ":id": token.outbox_id,
                    ":desired_action": token.action.as_str(),
                    ":mutation_sequence": token.mutation_sequence,
                    ":target_revision": token.target_revision,
                    ":target_content_hash": token.target_content_hash.as_deref(),
                    ":claimed_generation_id": token.generation_id.as_str(),
                    ":generation_authority_epoch": token.generation_authority_epoch,
                    ":generation_id": token.generation_id.as_str(),
                    ":descriptor_hash": token.descriptor_hash.as_str(),
                    ":dimension": token.dimension as i64,
                    ":lease_owner": token.lease_owner.as_str(),
                    ":lease_fence_epoch": token.fence_epoch,
                    ":fenced_claim_epoch": token.fenced_claim_epoch,
                    ":attempt_ordinal": token.attempt_ordinal,
                },
            )
            .map_err(|_| single_event_error())?;
        if changed == 1 {
            late_delete_resolution::ensure_runtime_resolution_for_delete_unknown_in(
                &tx,
                token.outbox_id,
            )
            .map_err(|_| single_event_error())?;
        }
        tx.commit().map_err(|_| single_event_error())?;
        #[cfg(test)]
        if changed == 1 && take_post_commit_delete_witness_fault_for_test() {
            return Err(single_event_error());
        }
        Ok(if changed == 1 {
            FencedDeleteWitnessResult::Marked
        } else {
            FencedDeleteWitnessResult::LostLeaseOrSuperseded
        })
    }

    /// Re-reads SQLite after an indeterminate Delete-witness commit result. It
    /// has no write path and cannot re-authorize the in-memory token.
    pub(crate) fn fenced_delete_send_witness_is_persisted(
        &self,
        token: &FencedAttemptToken,
    ) -> Result<bool, crate::storage::StorageError> {
        if token.action != MemoryVectorSyncAction::Delete {
            return Ok(false);
        }
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(|_| single_event_error())?;
        let current_now = authoritative_utc_millis_now_in(&tx)?;
        let persisted: Option<i64> = tx
            .query_row(
                &format!(
                    "SELECT 1 FROM memory_vector_sync_outbox
                     WHERE {FENCED_ATTEMPT_TOKEN_FINALIZE_IDENTITY}
                       AND last_send_disposition='possibly_sent'
                       AND delete_witness_at IS NOT NULL"
                ),
                rusqlite::named_params! {
                    ":current_now": current_now.as_str(),
                    ":id": token.outbox_id,
                    ":desired_action": token.action.as_str(),
                    ":mutation_sequence": token.mutation_sequence,
                    ":target_revision": token.target_revision,
                    ":target_content_hash": token.target_content_hash.as_deref(),
                    ":claimed_generation_id": token.generation_id.as_str(),
                    ":generation_authority_epoch": token.generation_authority_epoch,
                    ":generation_id": token.generation_id.as_str(),
                    ":descriptor_hash": token.descriptor_hash.as_str(),
                    ":dimension": token.dimension as i64,
                    ":lease_owner": token.lease_owner.as_str(),
                    ":lease_fence_epoch": token.fence_epoch,
                    ":fenced_claim_epoch": token.fenced_claim_epoch,
                    ":attempt_ordinal": token.attempt_ordinal,
                },
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| single_event_error())?;
        tx.commit().map_err(|_| single_event_error())?;
        Ok(persisted.is_some())
    }

    /// Commits a successful external Attempt only when the exact token remains
    /// current. The token predicate includes the reserved ordinal and marked
    /// claim epoch, so a same-owner claim renewal cannot complete a newer row.
    pub(crate) fn finalize_fenced_vector_sync(
        &self,
        token: &FencedAttemptToken,
    ) -> Result<FencedFinalizeResult, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let claim = token.claim_projection();
        if !fenced_attempt_token_current_in(&tx, &claim, token)? {
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(FencedFinalizeResult::LostLeaseOrSuperseded);
        }
        let current_now = authoritative_utc_millis_now_in(&tx)?;
        let result = match token.action {
            MemoryVectorSyncAction::Upsert => {
                let target_revision = token.target_revision.ok_or_else(single_event_error)?;
                let content_hash = token
                    .target_content_hash
                    .as_deref()
                    .ok_or_else(single_event_error)?;
                let changed = tx
                    .execute(
                        &format!(
                            "INSERT INTO memory_vector_generation_item (generation_id, life_id, memory_id, memory_revision, content_hash)
                             SELECT :generation_id, :life_id, :memory_id, :target_revision, :content_hash
                             WHERE EXISTS (SELECT 1 FROM memory_vector_sync_outbox WHERE {FENCED_ATTEMPT_TOKEN_FINALIZE_IDENTITY})
                             ON CONFLICT(generation_id, life_id, memory_id) DO UPDATE SET
                                memory_revision=excluded.memory_revision,
                                content_hash=excluded.content_hash,
                                updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')"
                        ),
                        rusqlite::named_params! {
                            ":content_hash": content_hash,
                            ":current_now": current_now.as_str(),
                            ":id": token.outbox_id,
                            ":life_id": token.life_id.as_str(),
                            ":memory_id": token.memory_id.as_str(),
                            ":desired_action": token.action.as_str(),
                            ":mutation_sequence": token.mutation_sequence,
                            ":target_revision": Some(target_revision),
                            ":target_content_hash": token.target_content_hash.as_deref(),
                            ":claimed_generation_id": token.generation_id.as_str(),
                            ":generation_authority_epoch": token.generation_authority_epoch,
                            ":generation_id": token.generation_id.as_str(),
                            ":descriptor_hash": token.descriptor_hash.as_str(),
                            ":dimension": token.dimension as i64,
                            ":lease_owner": token.lease_owner.as_str(),
                            ":lease_fence_epoch": token.fence_epoch,
                            ":fenced_claim_epoch": token.fenced_claim_epoch,
                            ":attempt_ordinal": token.attempt_ordinal,
                        },
                    )
                    .map_err(|_| single_event_error())?;
                if changed != 1 {
                    FencedFinalizeResult::LostLeaseOrSuperseded
                } else {
                    delete_fenced_attempt_outbox_in(&tx, token, &current_now)?
                }
            }
            MemoryVectorSyncAction::Delete => {
                tx.execute(
                    &format!(
                        "DELETE FROM memory_vector_generation_item
                         WHERE generation_id=:generation_id AND life_id=:life_id AND memory_id=:memory_id
                           AND EXISTS (SELECT 1 FROM memory_vector_sync_outbox WHERE {FENCED_ATTEMPT_TOKEN_FINALIZE_IDENTITY})"
                    ),
                    rusqlite::named_params! {
                        ":current_now": current_now.as_str(),
                        ":id": token.outbox_id,
                        ":life_id": token.life_id.as_str(),
                        ":memory_id": token.memory_id.as_str(),
                        ":desired_action": token.action.as_str(),
                        ":mutation_sequence": token.mutation_sequence,
                        ":target_revision": token.target_revision,
                        ":target_content_hash": token.target_content_hash.as_deref(),
                        ":claimed_generation_id": token.generation_id.as_str(),
                        ":generation_authority_epoch": token.generation_authority_epoch,
                        ":generation_id": token.generation_id.as_str(),
                        ":descriptor_hash": token.descriptor_hash.as_str(),
                        ":dimension": token.dimension as i64,
                        ":lease_owner": token.lease_owner.as_str(),
                        ":lease_fence_epoch": token.fence_epoch,
                        ":fenced_claim_epoch": token.fenced_claim_epoch,
                        ":attempt_ordinal": token.attempt_ordinal,
                    },
                )
                .map_err(|_| single_event_error())?;
                delete_fenced_attempt_outbox_in(&tx, token, &current_now)?
            }
        };
        tx.commit().map_err(|_| single_event_error())?;
        #[cfg(test)]
        if matches!(result, FencedFinalizeResult::Applied)
            && take_post_commit_success_finalize_fault_for_test()
        {
            return Err(single_event_error());
        }
        Ok(result)
    }

    /// Commits the durable classification of one failed external Attempt. A
    /// token is required even for retry scheduling, so an old failure cannot
    /// clear a newer claim's lease or overwrite its error evidence.
    pub(crate) fn finalize_fenced_vector_failure(
        &self,
        token: &FencedAttemptToken,
        error_code: &str,
        decision: FencedFailureDecision,
        send_disposition: Option<&str>,
        clock_now_millis: i64,
        drain_retry_cutoff_millis: i64,
    ) -> Result<FencedFailureFinalizeResult, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let claim = token.claim_projection();
        if !fenced_attempt_token_current_in(&tx, &claim, token)? {
            tx.commit().map_err(|_| single_event_error())?;
            return Ok(FencedFailureFinalizeResult::LostLeaseOrSuperseded);
        }
        let retry_at = match decision {
            FencedFailureDecision::RetryAfter { delay_millis }
                if clock_now_millis >= 0 && drain_retry_cutoff_millis >= 0 =>
            {
                let base = clock_now_millis.max(drain_retry_cutoff_millis);
                i64::try_from(delay_millis)
                    .ok()
                    .and_then(|delay| base.checked_add(delay))
            }
            _ => None,
        };
        let current_now = authoritative_utc_millis_now_in(&tx)?;
        let safe_error_code = safe_error_code(error_code);
        let result = if let Some(next_attempt_at_millis) = retry_at {
            let changed = tx
                .execute(
                    &format!(
                        "UPDATE memory_vector_sync_outbox
                         SET state='retry_wait',
                             next_attempt_at=strftime('%Y-%m-%dT%H:%M:%fZ', :next_attempt_at_millis / 1000.0, 'unixepoch'),
                             lease_owner=NULL, lease_expires_at=NULL, lease_fence_epoch=NULL,
                             last_error_code=:last_error_code,
                             last_send_disposition=:last_send_disposition,
                             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                          WHERE {FENCED_ATTEMPT_TOKEN_FINALIZE_IDENTITY}"
                    ),
                    rusqlite::named_params! {
                        ":next_attempt_at_millis": next_attempt_at_millis,
                        ":last_error_code": safe_error_code.as_str(),
                        ":last_send_disposition": send_disposition,
                        ":current_now": current_now.as_str(),
                        ":id": token.outbox_id,
                        ":desired_action": token.action.as_str(),
                        ":mutation_sequence": token.mutation_sequence,
                        ":target_revision": token.target_revision,
                        ":target_content_hash": token.target_content_hash.as_deref(),
                        ":claimed_generation_id": token.generation_id.as_str(),
                        ":generation_authority_epoch": token.generation_authority_epoch,
                        ":generation_id": token.generation_id.as_str(),
                        ":descriptor_hash": token.descriptor_hash.as_str(),
                        ":dimension": token.dimension as i64,
                        ":lease_owner": token.lease_owner.as_str(),
                        ":lease_fence_epoch": token.fence_epoch,
                        ":fenced_claim_epoch": token.fenced_claim_epoch,
                        ":attempt_ordinal": token.attempt_ordinal,
                    },
                )
                .map_err(|_| single_event_error())?;
            if changed == 1 {
                FencedFailureFinalizeResult::RetryScheduled {
                    next_attempt_at_millis,
                }
            } else {
                FencedFailureFinalizeResult::LostLeaseOrSuperseded
            }
        } else {
            let changed = tx
                .execute(
                    &format!(
                        "UPDATE memory_vector_sync_outbox
                         SET state='blocked', next_attempt_at=NULL,
                             lease_owner=NULL, lease_expires_at=NULL, lease_fence_epoch=NULL,
                             last_error_code=:last_error_code,
                             last_send_disposition=:last_send_disposition,
                             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                          WHERE {FENCED_ATTEMPT_TOKEN_FINALIZE_IDENTITY}"
                    ),
                    rusqlite::named_params! {
                        ":last_error_code": safe_error_code.as_str(),
                        ":last_send_disposition": send_disposition,
                        ":current_now": current_now.as_str(),
                        ":id": token.outbox_id,
                        ":desired_action": token.action.as_str(),
                        ":mutation_sequence": token.mutation_sequence,
                        ":target_revision": token.target_revision,
                        ":target_content_hash": token.target_content_hash.as_deref(),
                        ":claimed_generation_id": token.generation_id.as_str(),
                        ":generation_authority_epoch": token.generation_authority_epoch,
                        ":generation_id": token.generation_id.as_str(),
                        ":descriptor_hash": token.descriptor_hash.as_str(),
                        ":dimension": token.dimension as i64,
                        ":lease_owner": token.lease_owner.as_str(),
                        ":lease_fence_epoch": token.fence_epoch,
                        ":fenced_claim_epoch": token.fenced_claim_epoch,
                        ":attempt_ordinal": token.attempt_ordinal,
                    },
                )
                .map_err(|_| single_event_error())?;
            if changed == 1 {
                FencedFailureFinalizeResult::Blocked
            } else {
                FencedFailureFinalizeResult::LostLeaseOrSuperseded
            }
        };
        if token.action == MemoryVectorSyncAction::Delete {
            let canonical_unknown: bool = tx
                .query_row(
                    &format!(
                        "SELECT EXISTS(
                             SELECT 1 FROM memory_vector_sync_outbox
                             WHERE id=:id AND {DELETE_UNKNOWN_EVIDENCE_SQL}
                         )"
                    ),
                    rusqlite::named_params! { ":id": token.outbox_id },
                    |row| row.get(0),
                )
                .map_err(|_| single_event_error())?;
            if canonical_unknown {
                let has_witness_anchor: bool = tx
                    .query_row(
                        "SELECT EXISTS(
                             SELECT 1 FROM memory_vector_sync_outbox
                             WHERE id=?1 AND delete_witness_at IS NOT NULL
                         )",
                        [token.outbox_id],
                        |row| row.get(0),
                    )
                    .map_err(|_| single_event_error())?;
                if !has_witness_anchor {
                    return Err(crate::storage::StorageError::new(
                        "LATE_DELETE_RESOLUTION_INVARIANT_VIOLATION",
                        "canonical Delete-Unknown requires a durable pre-send witness",
                        true,
                    ));
                }
                late_delete_resolution::ensure_runtime_resolution_for_delete_unknown_in(
                    &tx,
                    token.outbox_id,
                )
                .map_err(|_| single_event_error())?;
            }
        }
        tx.commit().map_err(|_| single_event_error())?;
        #[cfg(test)]
        if !matches!(result, FencedFailureFinalizeResult::LostLeaseOrSuperseded)
            && take_post_commit_failure_finalize_fault_for_test()
        {
            return Err(single_event_error());
        }
        Ok(result)
    }

    /// The only claim-authorized terminal transition left in the worker path is
    /// pre-Attempt target staleness. It consumes no slot and cannot represent an
    /// external result, so it is deliberately separate from token finalization.
    pub(crate) fn block_fenced_vector_target_stale(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<FencedFinalizeResult, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let binding_row = match inspect_fenced_generation_binding_in(&tx, claim)? {
            FencedBindingCurrent::Current(row)
                if row.attempt_count == 0
                    && matches!(
                        row.attempt_identity_phase(),
                        AttemptIdentityPhase::ClaimUnmarked
                    ) =>
            {
                row
            }
            FencedBindingCurrent::Current(_) | FencedBindingCurrent::NotCurrent => {
                tx.commit().map_err(|_| single_event_error())?;
                return Ok(FencedFinalizeResult::LostLeaseOrSuperseded);
            }
        };
        let changed = tx
            .execute(
                &format!(
                    "UPDATE memory_vector_sync_outbox
                     SET state='blocked', next_attempt_at=NULL, lease_owner=NULL,
                         lease_expires_at=NULL, lease_fence_epoch=NULL,
                         claimed_generation_id=NULL, claimed_generation_authority_epoch=NULL, last_error_code='VECTOR_TARGET_STALE',
                         last_send_disposition=NULL,
                         updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                     WHERE {GENERATION_BINDING_CLAIM_IDENTITY}"
                ),
                rusqlite::named_params! {
                    ":id": binding_row.id,
                    ":desired_action": binding_row.desired_action.as_str(),
                    ":mutation_sequence": binding_row.mutation_sequence,
                    ":target_revision": binding_row.target_revision,
                    ":target_content_hash": binding_row.target_content_hash.as_deref(),
                    ":current_state": binding_row.state.as_str(),
                    ":attempt_count": binding_row.attempt_count,
                    ":claimed_generation_id": binding_row.claimed_generation_id.as_deref(),
                    ":lease_owner": binding_row.lease_owner.as_deref(),
                    ":lease_fence_epoch": binding_row.lease_fence_epoch,
                    ":lease_expires_at": binding_row.lease_expires_at.as_deref(),
                    ":fenced_claim_epoch": claim.fenced_claim_epoch,
                },
            )
            .map_err(|_| single_event_error())?;
        tx.commit().map_err(|_| single_event_error())?;
        Ok(if changed == 1 {
            FencedFinalizeResult::Applied
        } else {
            FencedFinalizeResult::LostLeaseOrSuperseded
        })
    }

    /// Rechecks only SQLite after a caller lost the success-finalize result.
    /// It never reserves or invokes any external dependency.
    pub(crate) fn fenced_success_finalize_is_applied(
        &self,
        token: &FencedAttemptToken,
    ) -> Result<bool, crate::storage::StorageError> {
        let state = self.state()?;
        let replacement_exists: Option<i64> = state
            .connection
            .query_row(
                "SELECT 1 FROM memory_vector_sync_outbox
                 WHERE id=?1 OR (life_id=?2 AND memory_id=?3)",
                params![token.outbox_id, token.life_id, token.memory_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| single_event_error())?;
        if replacement_exists.is_some() {
            return Ok(false);
        }
        match token.action {
            MemoryVectorSyncAction::Upsert => {
                let Some(target_revision) = token.target_revision else {
                    return Ok(false);
                };
                let Some(target_content_hash) = token.target_content_hash.as_deref() else {
                    return Ok(false);
                };
                state
                    .connection
                    .query_row(
                        "SELECT 1 FROM memory_vector_generation_item
                         WHERE generation_id=?1 AND life_id=?2 AND memory_id=?3
                           AND memory_revision=?4 AND content_hash=?5",
                        params![
                            token.generation_id,
                            token.life_id,
                            token.memory_id,
                            target_revision,
                            target_content_hash,
                        ],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map(|value| value.is_some())
                    .map_err(|_| single_event_error())
            }
            MemoryVectorSyncAction::Delete => state
                .connection
                .query_row(
                    "SELECT 1 FROM memory_vector_generation_item
                     WHERE generation_id=?1 AND life_id=?2 AND memory_id=?3",
                    params![token.generation_id, token.life_id, token.memory_id],
                    |row| row.get(0),
                )
                .optional()
                .map(|value: Option<i64>| value.is_none())
                .map_err(|_| single_event_error()),
        }
    }

    /// Rechecks the persisted failure transition after a post-commit result
    /// loss. The expected state is derived from the already chosen decision;
    /// no new claim, reservation, Provider, or Lance call is made.
    pub(crate) fn fenced_failure_finalize_is_applied(
        &self,
        token: &FencedAttemptToken,
        error_code: &str,
        decision: FencedFailureDecision,
        send_disposition: Option<&str>,
    ) -> Result<bool, crate::storage::StorageError> {
        let state = self.state()?;
        let row: Option<FencedFailureFinalizeSnapshot> = state
            .connection
            .query_row(
                "SELECT state, next_attempt_at, attempt_count, claimed_generation_id,
                        lease_owner, lease_fence_epoch, lease_expires_at,
                        last_error_code, last_marked_claim_epoch, fenced_claim_epoch,
                        last_send_disposition
                 FROM memory_vector_sync_outbox
                 WHERE id=?1 AND desired_action=?2 AND mutation_sequence=?3
                   AND target_revision IS ?4 AND target_content_hash IS ?5
                   AND migration_disposition IS NULL",
                params![
                    token.outbox_id,
                    token.action.as_str(),
                    token.mutation_sequence,
                    token.target_revision,
                    token.target_content_hash,
                ],
                |row| {
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
                },
            )
            .optional()
            .map_err(|_| single_event_error())?;
        let Some((
            state_name,
            next_attempt_at,
            attempt_count,
            claimed_generation_id,
            lease_owner,
            lease_fence_epoch,
            lease_expires_at,
            last_error_code,
            last_marked_claim_epoch,
            fenced_claim_epoch,
            last_send_disposition,
        )) = row
        else {
            return Ok(false);
        };
        let expected_state = match decision {
            FencedFailureDecision::RetryAfter { .. } => "retry_wait",
            FencedFailureDecision::Blocked => "blocked",
        };
        Ok(state_name == expected_state
            && (expected_state == "retry_wait") == next_attempt_at.is_some()
            && attempt_count == token.attempt_ordinal
            && claimed_generation_id.as_deref() == Some(token.generation_id.as_str())
            && lease_owner.is_none()
            && lease_fence_epoch.is_none()
            && lease_expires_at.is_none()
            && last_error_code.as_deref() == Some(safe_error_code(error_code).as_str())
            && last_marked_claim_epoch == token.fenced_claim_epoch
            && fenced_claim_epoch == token.fenced_claim_epoch
            && last_send_disposition.as_deref() == send_disposition)
    }

    #[cfg(test)]
    pub(crate) fn test_fail_next_fenced_success_finalize_after_commit(&self) {
        fail_next_success_finalize_after_commit_for_test();
    }

    #[cfg(test)]
    pub(crate) fn test_fail_next_fenced_failure_finalize_after_commit(&self) {
        fail_next_failure_finalize_after_commit_for_test();
    }

    #[cfg(test)]
    pub(crate) fn test_fail_next_fenced_reserve_after_commit_for_test(&self) {
        fail_next_reserve_after_commit_for_test();
    }

    #[cfg(test)]
    pub(crate) fn test_fail_next_fenced_delete_witness_after_commit(&self) {
        fail_next_delete_witness_after_commit_for_test();
    }

    #[cfg(test)]
    pub(crate) fn test_fail_next_enqueue_after_commit(&self) {
        fail_next_enqueue_after_commit_for_test();
    }

    /// Test-only convenience for fixtures that already hold a current claim.
    /// It calls the same idempotent reserve path as production, never constructs
    /// a token from test data, and therefore preserves the complete token CAS.
    #[cfg(test)]
    pub(crate) fn test_reserve_fenced_attempt_token(
        &self,
        claim: &FencedVectorSyncClaim,
    ) -> Result<FencedAttemptToken, crate::storage::StorageError> {
        match self.reserve_fenced_attempt(claim)? {
            FencedAttemptReservation::Reserved(token) => Ok(*token),
            FencedAttemptReservation::LostLeaseOrSuperseded
            | FencedAttemptReservation::BudgetExhausted => Err(single_event_error()),
        }
    }

    /// Compatibility for pre-ATT-I3 test fixtures only. Every terminal path
    /// first obtains the real idempotent reservation token; it never fabricates
    /// token fields from a claim or lets a claim bypass the token CAS.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn test_complete_claim_via_real_reserved_token(
        &self,
        claim: &FencedVectorSyncClaim,
        _content_hash: Option<&str>,
        error_code: Option<&str>,
        retry: bool,
        send_disposition: Option<&str>,
    ) -> Result<FencedFinalizeResult, crate::storage::StorageError> {
        if let Some(error_code) = error_code {
            return self
                .test_fail_claim_via_real_reserved_token(
                    claim,
                    error_code,
                    if retry {
                        FencedFailureDecision::RetryAfter {
                            delay_millis: 30_000,
                        }
                    } else {
                        FencedFailureDecision::Blocked
                    },
                    send_disposition,
                    0,
                    0,
                )
                .map(|result| match result {
                    FencedFailureFinalizeResult::LostLeaseOrSuperseded => {
                        FencedFinalizeResult::LostLeaseOrSuperseded
                    }
                    FencedFailureFinalizeResult::RetryScheduled { .. }
                    | FencedFailureFinalizeResult::Blocked => FencedFinalizeResult::Applied,
                });
        }
        match self.reserve_fenced_attempt(claim)? {
            FencedAttemptReservation::Reserved(token) => self.finalize_fenced_vector_sync(&token),
            FencedAttemptReservation::LostLeaseOrSuperseded
            | FencedAttemptReservation::BudgetExhausted => {
                Ok(FencedFinalizeResult::LostLeaseOrSuperseded)
            }
        }
    }

    /// Test-only adapter for legacy fixtures. It invokes the exact production
    /// token failure finalizer after authoritative reserve, including when a
    /// repeated reserve re-reads an already marked claim epoch.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn test_fail_claim_via_real_reserved_token(
        &self,
        claim: &FencedVectorSyncClaim,
        error_code: &str,
        decision: FencedFailureDecision,
        send_disposition: Option<&str>,
        clock_now_millis: i64,
        drain_retry_cutoff_millis: i64,
    ) -> Result<FencedFailureFinalizeResult, crate::storage::StorageError> {
        match self.reserve_fenced_attempt(claim)? {
            FencedAttemptReservation::Reserved(token) => self.finalize_fenced_vector_failure(
                &token,
                error_code,
                decision,
                send_disposition,
                clock_now_millis,
                drain_retry_cutoff_millis,
            ),
            FencedAttemptReservation::LostLeaseOrSuperseded
            | FencedAttemptReservation::BudgetExhausted => {
                Ok(FencedFailureFinalizeResult::LostLeaseOrSuperseded)
            }
        }
    }

    /// Test fixture that back-dates the Attempt budget to a chosen count.
    ///
    /// A positive count means slots were already reserved, so the current claim
    /// epoch is marked to match — otherwise the fixture would describe the
    /// impossible state "slots consumed, but no claim ever reserved one", which the
    /// schema-14 CHECK constraints and the Attempt-identity classifier both reject.
    #[cfg(test)]
    pub(crate) fn test_set_fenced_attempt_count(
        &self,
        attempt_count: i64,
    ) -> Result<(), crate::storage::StorageError> {
        let state = self.state()?;
        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET attempt_count=?1,
                     last_marked_claim_epoch=CASE WHEN ?1 > 0 THEN fenced_claim_epoch ELSE 0 END",
                params![attempt_count],
            )
            .map_err(|_| single_event_error())?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_set_fenced_state_for_generation_binding(
        &self,
        state_name: &str,
        clear_ephemeral_generation: bool,
    ) -> Result<(), crate::storage::StorageError> {
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let row = generation_binding_rows_in(&transaction, "1=1")?
            .into_iter()
            .next()
            .ok_or_else(single_event_error)?;
        let clear_ephemeral_generation =
            clear_ephemeral_generation && matches!(row.phase(), GenerationBindingPhase::Ephemeral);
        if clear_ephemeral_generation {
            transaction
                .execute(
                    "UPDATE memory_vector_sync_outbox
                 SET state=?1, lease_owner=NULL, lease_expires_at=NULL, lease_fence_epoch=NULL,
                     claimed_generation_id=NULL, claimed_generation_authority_epoch=NULL, next_attempt_at=NULL
                 WHERE id=?2 AND mutation_sequence=?3 AND state='processing' AND attempt_count=0
                   AND claimed_generation_id=?4 AND lease_owner=?5 AND lease_fence_epoch=?6
                   AND lease_expires_at=?7 AND migration_disposition IS NULL",
                    params![
                        state_name,
                        row.id,
                        row.mutation_sequence,
                        row.claimed_generation_id,
                        row.lease_owner,
                        row.lease_fence_epoch,
                        row.lease_expires_at,
                    ],
                )
                .map_err(|_| single_event_error())?;
        } else {
            transaction
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET state=?1, lease_owner=NULL, lease_expires_at=NULL, lease_fence_epoch=NULL,
                         next_attempt_at=NULL
                     WHERE id=?2 AND mutation_sequence=?3 AND state=?4 AND attempt_count=?5
                       AND claimed_generation_id IS ?6 AND lease_owner IS ?7
                       AND lease_fence_epoch IS ?8 AND lease_expires_at IS ?9
                       AND migration_disposition IS NULL",
                    params![
                        state_name,
                        row.id,
                        row.mutation_sequence,
                        row.state,
                        row.attempt_count,
                        row.claimed_generation_id,
                        row.lease_owner,
                        row.lease_fence_epoch,
                        row.lease_expires_at,
                    ],
                )
                .map_err(|_| single_event_error())?;
        }
        transaction.commit().map_err(|_| single_event_error())?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_recover_expired_fenced_processing_for_generation_binding(
        &self,
        retry_cutoff_millis: i64,
    ) -> Result<usize, crate::storage::StorageError> {
        let mut state = self.state()?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        let recovered =
            recover_expired_fenced_processing_in(&transaction, Some(retry_cutoff_millis))?;
        transaction.commit().map_err(|_| single_event_error())?;
        Ok(recovered)
    }

    #[cfg(test)]
    pub(crate) fn test_fenced_outbox_failure_snapshot(
        &self,
    ) -> Result<(i64, Option<String>, String), crate::storage::StorageError> {
        let state = self.state()?;
        state.connection.query_row(
            "SELECT attempt_count, last_send_disposition, last_error_code FROM memory_vector_sync_outbox",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .map_err(|_| single_event_error())
    }

    #[cfg(test)]
    pub(crate) fn test_expire_fenced_runtime_lease(
        &self,
    ) -> Result<(), crate::storage::StorageError> {
        let state = self.state()?;
        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_runtime_lease SET expires_at='2000-01-01T00:00:00.000Z'",
                [],
            )
            .map_err(|_| single_event_error())?;
        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET lease_expires_at='2000-01-01T00:00:00.000Z' WHERE state='processing'",
                [],
            )
            .map_err(|_| single_event_error())?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_fenced_completion_snapshot(
        &self,
    ) -> Result<(String, i64, i64), crate::storage::StorageError> {
        let state = self.state()?;
        let job = state
            .connection
            .query_row(
                "SELECT state, attempt_count FROM memory_vector_sync_outbox",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| single_event_error())?;
        let items = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_item",
                [],
                |row| row.get(0),
            )
            .map_err(|_| single_event_error())?;
        Ok((job.0, job.1, items))
    }

    #[cfg(test)]
    pub(crate) fn test_database_main_path(
        &self,
    ) -> Result<std::path::PathBuf, crate::storage::StorageError> {
        let state = self.state()?;
        state
            .connection
            .query_row(
                "SELECT file FROM pragma_database_list WHERE name='main'",
                [],
                |row| row.get::<_, String>(0),
            )
            .map(std::path::PathBuf::from)
            .map_err(|_| single_event_error())
    }

    /// Serializes the complete durable outbox row for one memory as a stable
    /// string so a read-only caller can prove it never mutated the database.
    #[cfg(test)]
    pub(crate) fn test_outbox_row_full_line(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<String, crate::storage::StorageError> {
        let state = self.state()?;
        let row: Vec<rusqlite::types::Value> = state
            .connection
            .query_row(
                "SELECT desired_action, state, attempt_count, mutation_sequence,
                        target_revision, target_content_hash, claimed_generation_id,
                        fenced_claim_epoch, last_marked_claim_epoch,
                        last_send_disposition, last_error_code, next_attempt_at,
                        lease_owner, lease_fence_epoch, lease_expires_at,
                        migration_disposition, created_at, updated_at
                 FROM memory_vector_sync_outbox WHERE life_id=?1 AND memory_id=?2",
                params![life_id, memory_id],
                |r| {
                    (0..18)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<Result<Vec<_>, _>>()
                },
            )
            .map_err(|_| single_event_error())?;
        Ok(row
            .iter()
            .map(|value| format!("{value:?}"))
            .collect::<Vec<_>>()
            .join("|"))
    }

    #[cfg(test)]
    pub(crate) fn test_get_outbox_snapshot_detailed(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<OutboxSnapshotDetailed, crate::storage::StorageError> {
        let state = self.state()?;
        let total_count: usize = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox",
                [],
                |row| row.get(0),
            )
            .map_err(|_| single_event_error())?;
        let row = state.connection.query_row(
            "SELECT id, desired_action, mutation_sequence, target_revision, target_content_hash,
                    state, attempt_count, lease_owner, lease_fence_epoch, lease_expires_at, claimed_generation_id,
                    (claimed_generation_id IS NULL), migration_disposition, last_error_code, last_send_disposition, next_attempt_at,
                    fenced_claim_epoch, last_marked_claim_epoch, delete_witness_at, updated_at
             FROM memory_vector_sync_outbox WHERE life_id=?1 AND memory_id=?2",
            params![life_id, memory_id],
            |r| {
                Ok((
                    r.get(0)?,
                    r.get(1)?,
                    r.get(2)?,
                    r.get(3)?,
                    r.get(4)?,
                    r.get(5)?,
                    r.get(6)?,
                    r.get(7)?,
                    r.get(8)?,
                    r.get(9)?,
                    r.get(10)?,
                    r.get::<_, i64>(11)? == 1,
                    r.get(12)?,
                    r.get(13)?,
                    r.get(14)?,
                    r.get(15)?,
                    r.get(16)?,
                    r.get(17)?,
                    r.get(18)?,
                    r.get(19)?,
                ))
            },
        ).map_err(|_| single_event_error())?;
        Ok(OutboxSnapshotDetailed {
            total_count,
            id: row.0,
            desired_action: row.1,
            mutation_sequence: row.2,
            target_revision: row.3,
            target_content_hash: row.4,
            state: row.5,
            attempt_count: row.6,
            lease_owner: row.7,
            lease_fence_epoch: row.8,
            lease_expires_at: row.9,
            claimed_generation_id: row.10,
            claimed_generation_id_is_null: row.11,
            migration_disposition: row.12,
            last_error_code: row.13,
            last_send_disposition: row.14,
            next_attempt_at: row.15,
            fenced_claim_epoch: row.16,
            last_marked_claim_epoch: row.17,
            delete_witness_at: row.18,
            updated_at: row.19,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_insert_legacy_quarantine_fixture(
        &self,
        life_id: &str,
        memory_id: &str,
    ) -> Result<i64, crate::storage::StorageError> {
        let mut state = self.state()?;
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| single_event_error())?;
        tx.execute(
            "INSERT OR IGNORE INTO memory_vector_sync_mutation_clock (singleton, last_sequence) VALUES (1, 0)",
            [],
        )
        .map_err(|_| single_event_error())?;
        tx.execute(
            "UPDATE memory_vector_sync_mutation_clock SET last_sequence = last_sequence + 1 WHERE singleton = 1",
            [],
        )
        .map_err(|_| single_event_error())?;
        let sequence: i64 = tx
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .map_err(|_| single_event_error())?;
        tx.execute(
            "INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, mutation_sequence, target_revision, target_content_hash, migration_disposition)
             VALUES (?1, ?2, 'upsert', 'blocked', 0, ?3, NULL, NULL, 'legacy_upsert_rebuild_required')
             ON CONFLICT(life_id, memory_id) DO UPDATE SET
               desired_action='upsert', state='blocked', attempt_count=0, mutation_sequence=?3,
               target_revision=NULL, target_content_hash=NULL, migration_disposition='legacy_upsert_rebuild_required',
               lease_owner=NULL, lease_expires_at=NULL, lease_fence_epoch=NULL, claimed_generation_id=NULL, claimed_generation_authority_epoch=NULL,
               updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')",
            params![life_id, memory_id, sequence],
        ).map_err(|_| single_event_error())?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(|_| single_event_error())?;
        Ok(id)
    }

    #[cfg(test)]
    pub(crate) fn test_generation_item_count(&self) -> Result<usize, crate::storage::StorageError> {
        let state = self.state()?;
        state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_generation_item",
                [],
                |r| r.get(0),
            )
            .map_err(|_| single_event_error())
    }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OutboxSnapshotDetailed {
    pub total_count: usize,
    pub id: i64,
    pub desired_action: String,
    pub mutation_sequence: i64,
    pub target_revision: Option<i64>,
    pub target_content_hash: Option<String>,
    pub state: String,
    pub attempt_count: i64,
    pub lease_owner: Option<String>,
    pub lease_fence_epoch: Option<i64>,
    pub lease_expires_at: Option<String>,
    pub claimed_generation_id: Option<String>,
    pub claimed_generation_id_is_null: bool,
    pub migration_disposition: Option<String>,
    pub last_error_code: Option<String>,
    pub last_send_disposition: Option<String>,
    pub next_attempt_at: Option<String>,
    pub fenced_claim_epoch: i64,
    pub last_marked_claim_epoch: i64,
    pub delete_witness_at: Option<String>,
    pub updated_at: String,
}

#[allow(dead_code)]
fn acquire_runtime_lease(
    tx: &Transaction<'_>,
    owner: &str,
) -> Result<i64, crate::storage::StorageError> {
    tx.execute("INSERT OR IGNORE INTO memory_vector_sync_runtime_lease (lease_name, fence_epoch) VALUES ('memory-vector-single-event-consumer', 0)", []).map_err(|_| single_event_error())?;
    let renewed = tx.execute(
        "UPDATE memory_vector_sync_runtime_lease SET
         expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+120 seconds'), updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE lease_name='memory-vector-single-event-consumer' AND owner_id=?1
           AND expires_at > strftime('%Y-%m-%dT%H:%M:%fZ','now')",
        params![owner],
    ).map_err(|_| single_event_error())?;
    if renewed == 1 {
        return tx.query_row(
            "SELECT fence_epoch FROM memory_vector_sync_runtime_lease WHERE lease_name='memory-vector-single-event-consumer' AND owner_id=?1",
            params![owner], |row| row.get(0),
        ).map_err(|_| single_event_error());
    }
    let acquired = tx.execute(
        "UPDATE memory_vector_sync_runtime_lease SET owner_id=?1, fence_epoch=fence_epoch+1,
         expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','+120 seconds'), updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
         WHERE lease_name='memory-vector-single-event-consumer' AND fence_epoch < 9223372036854775807
           AND (owner_id IS NULL OR expires_at IS NULL OR expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ','now'))",
        params![owner],
    ).map_err(|_| single_event_error())?;
    if acquired != 1 {
        return Err(single_event_error());
    }
    tx.query_row(
        "SELECT fence_epoch FROM memory_vector_sync_runtime_lease WHERE lease_name='memory-vector-single-event-consumer' AND owner_id=?1",
        params![owner], |row| row.get(0),
    ).map_err(|_| single_event_error())
}

fn authoritative_utc_millis_now_in(
    tx: &Transaction<'_>,
) -> Result<String, crate::storage::StorageError> {
    tx.query_row("SELECT strftime('%Y-%m-%dT%H:%M:%fZ','now')", [], |row| {
        row.get(0)
    })
    .map_err(|_| single_event_error())
}

fn lease_is_current_at(expires_at: Option<&str>, now: &str) -> bool {
    is_valid_utc_millis_timestamp(now)
        && expires_at.is_some_and(|value| is_valid_utc_millis_timestamp(value) && value > now)
}

fn fenced_claim_current_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
) -> Result<bool, crate::storage::StorageError> {
    // SQLite creates this canonical UTC-millisecond value once. Both lease
    // comparisons below use that same captured value, after strict structural
    // validation makes lexical comparison a comparison of the frozen encoding
    // rather than an assumption about arbitrary text.
    let now = authoritative_utc_millis_now_in(tx)?;
    let leases: Option<(Option<String>, Option<String>)> = tx
        .query_row(
            "SELECT o.lease_expires_at, r.expires_at
               FROM memory_vector_sync_outbox AS o
               JOIN memory_vector_sync_runtime_lease AS r
                 ON r.lease_name='memory-vector-single-event-consumer'
               JOIN memory_vector_generation AS g
                 ON g.generation_id=o.claimed_generation_id
              WHERE o.id=?1 AND o.desired_action=?2 AND o.mutation_sequence=?3
                AND o.state='processing' AND o.lease_owner=?4 AND o.lease_fence_epoch=?5
                AND o.claimed_generation_id=?6
                AND o.claimed_generation_authority_epoch IS ?11
                AND o.target_revision IS ?7 AND o.target_content_hash IS ?8
                AND o.migration_disposition IS NULL
                AND g.descriptor_hash=?9 AND g.dimension=?10
                AND ((?11 IS NULL AND g.state='building')
                     OR (?11 IS NOT NULL AND g.state='active' AND g.authority_epoch=?11
                         AND EXISTS (SELECT 1 FROM memory_vector_generation_authority a
                                     WHERE a.singleton=1 AND a.active_generation_id=g.generation_id)))
                 AND r.owner_id=?4 AND r.fence_epoch=?5
                 AND o.fenced_claim_epoch=?12",
            params![
                claim.id,
                claim.action.as_str(),
                claim.mutation_sequence,
                claim.lease_owner,
                claim.fence_epoch,
                claim.generation_id,
                claim.target_revision,
                claim.target_content_hash,
                claim.descriptor_hash,
                claim.dimension as i64,
                claim.generation_authority_epoch,
                claim.fenced_claim_epoch,
            ],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| single_event_error())?;
    let Some((outbox_expires_at, runtime_expires_at)) = leases else {
        return Ok(false);
    };
    Ok(lease_is_current_at(outbox_expires_at.as_deref(), &now)
        && lease_is_current_at(runtime_expires_at.as_deref(), &now))
}

const GENERATION_BINDING_ROW_COLUMNS: &str = "id, desired_action, mutation_sequence, target_revision, target_content_hash, state, attempt_count, claimed_generation_id, claimed_generation_authority_epoch, lease_owner, lease_fence_epoch, lease_expires_at, last_send_disposition, last_error_code, fenced_claim_epoch, last_marked_claim_epoch";
const GENERATION_BINDING_ROW_IDENTITY: &str = "id=:id AND desired_action=:desired_action AND mutation_sequence=:mutation_sequence AND target_revision IS :target_revision AND target_content_hash IS :target_content_hash AND state=:current_state AND attempt_count=:attempt_count AND claimed_generation_id IS :claimed_generation_id AND lease_owner IS :lease_owner AND lease_fence_epoch IS :lease_fence_epoch AND lease_expires_at IS :lease_expires_at AND migration_disposition IS NULL";
/// Exact identity for an operation that is authorized by a
/// [`FencedVectorSyncClaim`]. Unlike a general row-snapshot CAS, this must pin
/// the claim epoch so an old claim with a reused owner/runtime fence can never
/// mutate the newer claim cycle.
const GENERATION_BINDING_CLAIM_IDENTITY: &str = "id=:id AND desired_action=:desired_action AND mutation_sequence=:mutation_sequence AND target_revision IS :target_revision AND target_content_hash IS :target_content_hash AND state=:current_state AND attempt_count=:attempt_count AND claimed_generation_id IS :claimed_generation_id AND lease_owner IS :lease_owner AND lease_fence_epoch IS :lease_fence_epoch AND lease_expires_at IS :lease_expires_at AND fenced_claim_epoch=:fenced_claim_epoch AND migration_disposition IS NULL";
/// The success/failure terminal CAS for a durably reserved external Attempt.
/// It carries the full token identity, the persisted reservation ordinal and
/// marked claim epoch, both live leases, and the explicit building generation.
/// Unlike the older claim identity, it cannot authorize a pre-Attempt row.
const FENCED_ATTEMPT_TOKEN_FINALIZE_IDENTITY: &str = "id=:id AND desired_action=:desired_action AND mutation_sequence=:mutation_sequence AND target_revision IS :target_revision AND target_content_hash IS :target_content_hash AND state='processing' AND attempt_count=:attempt_ordinal AND claimed_generation_id=:claimed_generation_id AND lease_owner=:lease_owner AND lease_fence_epoch=:lease_fence_epoch AND fenced_claim_epoch=:fenced_claim_epoch AND last_marked_claim_epoch=:fenced_claim_epoch AND migration_disposition IS NULL AND lease_expires_at > :current_now AND EXISTS (SELECT 1 FROM memory_vector_sync_runtime_lease WHERE lease_name='memory-vector-single-event-consumer' AND owner_id=:lease_owner AND fence_epoch=:lease_fence_epoch AND expires_at > :current_now) AND ((:generation_authority_epoch IS NULL AND claimed_generation_authority_epoch IS NULL AND EXISTS (SELECT 1 FROM memory_vector_generation WHERE generation_id=:generation_id AND descriptor_hash=:descriptor_hash AND dimension=:dimension AND state='building')) OR (:generation_authority_epoch IS NOT NULL AND claimed_generation_authority_epoch=:generation_authority_epoch AND EXISTS (SELECT 1 FROM memory_vector_generation_authority a JOIN memory_vector_generation g ON g.generation_id=a.active_generation_id WHERE a.singleton=1 AND a.active_generation_id=:generation_id AND g.descriptor_hash=:descriptor_hash AND g.dimension=:dimension AND g.state='active' AND g.authority_epoch=:generation_authority_epoch)))";
/// Adds the two claim-epoch columns to [`GENERATION_BINDING_ROW_IDENTITY`] for
/// callers that must also pin the exact Attempt-identity snapshot (reserve and
/// its idempotent guard). Kept as a distinct predicate rather than widening the
/// shared identity string, so every other caller's CAS surface is unchanged.
const GENERATION_BINDING_ROW_IDENTITY_WITH_ATTEMPT_EPOCHS: &str = "id=:id AND desired_action=:desired_action AND mutation_sequence=:mutation_sequence AND target_revision IS :target_revision AND target_content_hash IS :target_content_hash AND state=:current_state AND attempt_count=:attempt_count AND claimed_generation_id IS :claimed_generation_id AND lease_owner IS :lease_owner AND lease_fence_epoch IS :lease_fence_epoch AND lease_expires_at IS :lease_expires_at AND fenced_claim_epoch=:fenced_claim_epoch AND last_marked_claim_epoch=:last_marked_claim_epoch AND migration_disposition IS NULL";

fn delete_fenced_attempt_outbox_in(
    tx: &Transaction<'_>,
    token: &FencedAttemptToken,
    current_now: &str,
) -> Result<FencedFinalizeResult, crate::storage::StorageError> {
    let changed = tx
        .execute(
            &format!(
                "DELETE FROM memory_vector_sync_outbox
                 WHERE {FENCED_ATTEMPT_TOKEN_FINALIZE_IDENTITY}"
            ),
            rusqlite::named_params! {
                ":current_now": current_now,
                ":id": token.outbox_id,
                ":desired_action": token.action.as_str(),
                ":mutation_sequence": token.mutation_sequence,
                ":target_revision": token.target_revision,
                ":target_content_hash": token.target_content_hash.as_deref(),
                ":claimed_generation_id": token.generation_id.as_str(),
                ":generation_authority_epoch": token.generation_authority_epoch,
                ":generation_id": token.generation_id.as_str(),
                ":descriptor_hash": token.descriptor_hash.as_str(),
                ":dimension": token.dimension as i64,
                ":lease_owner": token.lease_owner.as_str(),
                ":lease_fence_epoch": token.fence_epoch,
                ":fenced_claim_epoch": token.fenced_claim_epoch,
                ":attempt_ordinal": token.attempt_ordinal,
            },
        )
        .map_err(|_| single_event_error())?;
    Ok(if changed == 1 {
        FencedFinalizeResult::Applied
    } else {
        FencedFinalizeResult::LostLeaseOrSuperseded
    })
}

fn generation_binding_row_from_row(row: &Row<'_>) -> rusqlite::Result<GenerationBindingRow> {
    Ok(GenerationBindingRow {
        id: row.get(0)?,
        desired_action: row.get(1)?,
        mutation_sequence: row.get(2)?,
        target_revision: row.get(3)?,
        target_content_hash: row.get(4)?,
        state: row.get(5)?,
        attempt_count: row.get(6)?,
        claimed_generation_id: row.get(7)?,
        claimed_generation_authority_epoch: row.get(8)?,
        lease_owner: row.get(9)?,
        lease_fence_epoch: row.get(10)?,
        lease_expires_at: row.get(11)?,
        last_send_disposition: row.get(12)?,
        last_error_code: row.get(13)?,
        fenced_claim_epoch: row.get(14)?,
        last_marked_claim_epoch: row.get(15)?,
    })
}

fn generation_binding_rows_in(
    tx: &Transaction<'_>,
    predicate: &str,
) -> Result<Vec<GenerationBindingRow>, crate::storage::StorageError> {
    let mut statement = tx
        .prepare(&format!(
            "SELECT {GENERATION_BINDING_ROW_COLUMNS} FROM memory_vector_sync_outbox WHERE migration_disposition IS NULL AND {predicate} ORDER BY mutation_sequence ASC, id ASC"
        ))
        .map_err(|_| single_event_error())?;
    let rows = statement
        .query_map([], generation_binding_row_from_row)
        .map_err(|_| single_event_error())?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|_| single_event_error())
}

fn generation_binding_row_for_claim_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
) -> Result<Option<GenerationBindingRow>, crate::storage::StorageError> {
    tx.query_row(
        &format!(
            "SELECT {GENERATION_BINDING_ROW_COLUMNS} FROM memory_vector_sync_outbox WHERE id=?1 AND desired_action=?2 AND mutation_sequence=?3 AND target_revision IS ?4 AND target_content_hash IS ?5 AND fenced_claim_epoch=?6 AND migration_disposition IS NULL"
        ),
        params![
            claim.id,
            claim.action.as_str(),
            claim.mutation_sequence,
            claim.target_revision,
            claim.target_content_hash,
            claim.fenced_claim_epoch,
        ],
        generation_binding_row_from_row,
    )
    .optional()
    .map_err(|_| single_event_error())
}

fn binding_row_has_claim_processing_lease(
    row: &GenerationBindingRow,
    claim: &FencedVectorSyncClaim,
) -> bool {
    row.state == "processing"
        && row.lease_owner.as_deref() == Some(claim.lease_owner.as_str())
        && row.lease_fence_epoch == Some(claim.fence_epoch)
        && row.fenced_claim_epoch == claim.fenced_claim_epoch
}

fn block_generation_binding_scan_snapshot_in(
    tx: &Transaction<'_>,
    row: &GenerationBindingRow,
) -> Result<InvariantBlockOutcome, crate::storage::StorageError> {
    // Generation-binding corruption and Attempt-identity corruption are both
    // INTERNAL_INVARIANT: an impossible epoch relation or an over-budget count is
    // no more runnable than a missing durable generation.
    let binding_invalid = matches!(
        row.phase(),
        GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid
    );
    let attempt_identity_invalid =
        matches!(row.attempt_identity_phase(), AttemptIdentityPhase::Invalid);
    if !binding_invalid && !attempt_identity_invalid {
        return Ok(InvariantBlockOutcome::NotInvariant);
    }
    let changed = tx
        .execute(
            &format!(
                "UPDATE memory_vector_sync_outbox
                 SET state='blocked', next_attempt_at=NULL, lease_owner=NULL,
                     lease_expires_at=NULL, lease_fence_epoch=NULL,
                     last_error_code='INTERNAL_INVARIANT',
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE {GENERATION_BINDING_ROW_IDENTITY}"
            ),
            rusqlite::named_params! {
                ":id": row.id,
                ":desired_action": row.desired_action.as_str(),
                ":mutation_sequence": row.mutation_sequence,
                ":target_revision": row.target_revision,
                ":target_content_hash": row.target_content_hash.as_deref(),
                ":current_state": row.state.as_str(),
                ":attempt_count": row.attempt_count,
                ":claimed_generation_id": row.claimed_generation_id.as_deref(),
                ":lease_owner": row.lease_owner.as_deref(),
                ":lease_fence_epoch": row.lease_fence_epoch,
                ":lease_expires_at": row.lease_expires_at.as_deref(),
            },
        )
        .map_err(|_| single_event_error())?;
    Ok(if changed == 1 {
        InvariantBlockOutcome::Applied
    } else {
        InvariantBlockOutcome::Superseded
    })
}

fn block_generation_binding_claim_identity_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
    observed: &GenerationBindingRow,
) -> Result<InvariantBlockOutcome, crate::storage::StorageError> {
    // A worker may quarantine only the lease identity it actually owns. The
    // observed generation/attempt/expiry form an additional CAS snapshot, but
    // mutation, target, owner, and fence always come from the original claim.
    if !binding_row_has_claim_processing_lease(observed, claim)
        || observed.fenced_claim_epoch != claim.fenced_claim_epoch
    {
        return Ok(InvariantBlockOutcome::Superseded);
    }
    let generation_mismatch =
        observed.claimed_generation_id.as_deref() != Some(claim.generation_id());
    if !generation_mismatch
        && !matches!(
            observed.phase(),
            GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid
        )
        // Attempt-identity corruption is quarantined on the same footing as
        // generation-binding corruption, so an over-budget count or an impossible
        // epoch relation cannot stay in `processing`.
        && !matches!(
            observed.attempt_identity_phase(),
            AttemptIdentityPhase::Invalid
        )
    {
        return Ok(InvariantBlockOutcome::NotInvariant);
    }
    let changed = tx
        .execute(
            "UPDATE memory_vector_sync_outbox
             SET state='blocked', next_attempt_at=NULL, lease_owner=NULL,
                 lease_expires_at=NULL, lease_fence_epoch=NULL,
                 last_error_code='INTERNAL_INVARIANT',
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE id=?1 AND desired_action=?2 AND mutation_sequence=?3
               AND target_revision IS ?4 AND target_content_hash IS ?5
               AND state='processing' AND lease_owner=?6 AND lease_fence_epoch=?7
               AND attempt_count=?8 AND claimed_generation_id IS ?9
                AND lease_expires_at IS ?10 AND fenced_claim_epoch=?11
                AND migration_disposition IS NULL",
            params![
                claim.id,
                claim.action.as_str(),
                claim.mutation_sequence,
                claim.target_revision,
                claim.target_content_hash,
                claim.lease_owner,
                claim.fence_epoch,
                observed.attempt_count,
                observed.claimed_generation_id.as_deref(),
                observed.lease_expires_at.as_deref(),
                claim.fenced_claim_epoch,
            ],
        )
        .map_err(|_| single_event_error())?;
    Ok(if changed == 1 {
        InvariantBlockOutcome::Applied
    } else {
        InvariantBlockOutcome::Superseded
    })
}

fn quarantine_generation_binding_invariants_in(
    tx: &Transaction<'_>,
) -> Result<usize, crate::storage::StorageError> {
    let rows = generation_binding_rows_in(tx, "state IN ('pending','retry_wait','processing')")?;
    let mut quarantined = 0;
    for row in rows {
        if matches!(
            block_generation_binding_scan_snapshot_in(tx, &row)?,
            InvariantBlockOutcome::Applied
        ) {
            quarantined += 1;
        }
    }
    Ok(quarantined)
}

/// Converges every row whose Attempt budget is spent to a stable `blocked` state,
/// exactly once, before candidate selection.
///
/// Only rows that could otherwise still enter ordinary execution or manual retry
/// are considered: `pending`, `retry_wait`, and `failed`. A `processing` row with
/// `attempt_count == MAX_VECTOR_SYNC_ATTEMPTS` is deliberately untouched — it is
/// executing its fifth reserved Attempt, and destroying its claim here would
/// break a live worker.
///
/// Attempt count, generation, mutation, target, and both claim epochs are all
/// preserved; only the state, lease, and schedule converge. Because the CAS
/// snapshot includes the current state, a row already `blocked` cannot be
/// converged twice, so this never manufactures repeated drain work.
fn converge_exhausted_attempt_budget_in(
    tx: &Transaction<'_>,
) -> Result<usize, crate::storage::StorageError> {
    // The predicate is built from the compile-time budget constant, never from
    // caller input, so this stays a fixed statement shape.
    let rows = generation_binding_rows_in(
        tx,
        &format!(
            "attempt_count >= {MAX_VECTOR_SYNC_ATTEMPTS} AND state IN ('pending','retry_wait','failed')"
        ),
    )?;
    let mut converged = 0;
    for row in rows {
        // An identity-corrupt row (which includes attempt_count > the budget) is
        // the invariant scan's business, not the budget's. `failed` rows are
        // intentionally included in the budget scan but are not candidates, so
        // repair them here as well instead of leaving an over-budget failure
        // stranded outside ordinary claim processing.
        if matches!(row.attempt_identity_phase(), AttemptIdentityPhase::Invalid)
            || matches!(
                row.phase(),
                GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid
            )
        {
            if matches!(
                block_generation_binding_scan_snapshot_in(tx, &row)?,
                InvariantBlockOutcome::Applied
            ) {
                converged += 1;
            }
            continue;
        }
        converged += usize::from(matches!(
            converge_exhausted_attempt_budget_row_in(tx, &row)?,
            InvariantBlockOutcome::Applied
        ));
    }
    Ok(converged)
}

/// Returns the stable error that must remain visible when an Attempt budget is
/// exhausted. An Unknown upsert send is the strongest outcome; otherwise a
/// previously-classified permanent error is more useful than a generic budget
/// marker.
fn exhausted_attempt_budget_error_code(row: &GenerationBindingRow) -> &str {
    if is_unknown_upsert_send(row) || is_delete_unknown_row(row) {
        "PROVIDER_RESULT_UNKNOWN"
    } else {
        match row.last_error_code.as_deref() {
            Some(existing) if PERMANENT_ERROR_CODES.contains(&existing) => existing,
            _ => "MAX_ATTEMPTS",
        }
    }
}

/// Applies the non-invariant, at-limit convergence for one exact row snapshot.
/// It is shared by ordinary claim processing and manual retry so a terminal
/// budget cannot be left in a runnable state through an alternate entry point.
fn converge_exhausted_attempt_budget_row_in(
    tx: &Transaction<'_>,
    row: &GenerationBindingRow,
) -> Result<InvariantBlockOutcome, crate::storage::StorageError> {
    let changed = tx
        .execute(
            &format!(
                "UPDATE memory_vector_sync_outbox
                 SET state='blocked', next_attempt_at=NULL, lease_owner=NULL,
                     lease_expires_at=NULL, lease_fence_epoch=NULL,
                     last_error_code=:last_error_code,
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE {GENERATION_BINDING_ROW_IDENTITY}"
            ),
            rusqlite::named_params! {
                ":last_error_code": exhausted_attempt_budget_error_code(row),
                ":id": row.id,
                ":desired_action": row.desired_action.as_str(),
                ":mutation_sequence": row.mutation_sequence,
                ":target_revision": row.target_revision,
                ":target_content_hash": row.target_content_hash.as_deref(),
                ":current_state": row.state.as_str(),
                ":attempt_count": row.attempt_count,
                ":claimed_generation_id": row.claimed_generation_id.as_deref(),
                ":lease_owner": row.lease_owner.as_deref(),
                ":lease_fence_epoch": row.lease_fence_epoch,
                ":lease_expires_at": row.lease_expires_at.as_deref(),
            },
        )
        .map_err(|_| single_event_error())?;
    Ok(if changed == 1 {
        InvariantBlockOutcome::Applied
    } else {
        InvariantBlockOutcome::Superseded
    })
}

fn quarantine_malformed_target_bindings_in(
    tx: &Transaction<'_>,
) -> Result<usize, crate::storage::StorageError> {
    let rows = generation_binding_rows_in(
        tx,
        "desired_action='upsert' AND (target_revision IS NULL OR target_content_hash IS NULL) AND state IN ('pending','retry_wait','processing')",
    )?;
    let mut quarantined = 0;
    for row in rows {
        match row.phase() {
            GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid => {
                if matches!(
                    block_generation_binding_scan_snapshot_in(tx, &row)?,
                    InvariantBlockOutcome::Applied
                ) {
                    quarantined += 1;
                }
            }
            GenerationBindingPhase::Unbound
            | GenerationBindingPhase::Ephemeral
            | GenerationBindingPhase::Durable => {
                let clear_ephemeral = matches!(row.phase(), GenerationBindingPhase::Ephemeral);
                let assignment = if clear_ephemeral {
                    "claimed_generation_id=NULL, claimed_generation_authority_epoch=NULL,"
                } else {
                    ""
                };
                let changed = tx
                    .execute(
                        &format!(
                            "UPDATE memory_vector_sync_outbox
                             SET state='blocked', next_attempt_at=NULL, lease_owner=NULL,
                                 lease_expires_at=NULL, lease_fence_epoch=NULL,
                                 {assignment}
                                 last_error_code='VECTOR_TARGET_BINDING_MISSING',
                                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                             WHERE {GENERATION_BINDING_ROW_IDENTITY}"
                        ),
                        rusqlite::named_params! {
                            ":id": row.id,
                            ":desired_action": row.desired_action.as_str(),
                            ":mutation_sequence": row.mutation_sequence,
                            ":target_revision": row.target_revision,
                            ":target_content_hash": row.target_content_hash.as_deref(),
                            ":current_state": row.state.as_str(),
                            ":attempt_count": row.attempt_count,
                            ":claimed_generation_id": row.claimed_generation_id.as_deref(),
                            ":lease_owner": row.lease_owner.as_deref(),
                            ":lease_fence_epoch": row.lease_fence_epoch,
                            ":lease_expires_at": row.lease_expires_at.as_deref(),
                        },
                    )
                    .map_err(|_| single_event_error())?;
                quarantined += usize::from(changed == 1);
            }
        }
    }
    Ok(quarantined)
}

/// Pure currentness check for claim and token guards. It deliberately does not
/// reuse the quarantine-capable inspector below: stale or malformed evidence is
/// sufficient to reject a guard, but never authority to mutate an outbox row.
fn inspect_fenced_generation_binding_read_only_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
) -> Result<FencedBindingCurrent, crate::storage::StorageError> {
    let Some(row) = generation_binding_row_for_claim_in(tx, claim)? else {
        return Ok(FencedBindingCurrent::NotCurrent);
    };
    if !binding_row_has_claim_processing_lease(&row, claim) {
        return Ok(FencedBindingCurrent::NotCurrent);
    }
    let phase = row.phase();
    let matches_claim_generation =
        row.claimed_generation_id.as_deref() == Some(claim.generation_id());
    let matches_claim_epoch =
        row.claimed_generation_authority_epoch == claim.generation_authority_epoch;
    if matches!(
        phase,
        GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid
    ) || !matches_claim_generation
        || !matches_claim_epoch
        || !fenced_claim_current_in(tx, claim)?
    {
        return Ok(FencedBindingCurrent::NotCurrent);
    }
    match phase {
        GenerationBindingPhase::Ephemeral | GenerationBindingPhase::Durable => {
            Ok(FencedBindingCurrent::Current(Box::new(row)))
        }
        GenerationBindingPhase::Unbound
        | GenerationBindingPhase::MissingAfterAttempt
        | GenerationBindingPhase::Invalid => Ok(FencedBindingCurrent::NotCurrent),
    }
}

/// Quarantine-capable inspector for an authority path that owns the exact
/// claim identity. Guards must use [`inspect_fenced_generation_binding_read_only_in`]
/// instead.
fn inspect_fenced_generation_binding_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
) -> Result<FencedBindingCurrent, crate::storage::StorageError> {
    let Some(row) = generation_binding_row_for_claim_in(tx, claim)? else {
        return Ok(FencedBindingCurrent::NotCurrent);
    };
    // A stale owner, fence, mutation, target, state, or migration boundary is
    // never evidence that the current row is corrupt. It belongs to a newer
    // worker or mutation and must remain untouched by this claim.
    if !binding_row_has_claim_processing_lease(&row, claim) {
        return Ok(FencedBindingCurrent::NotCurrent);
    }
    let phase = row.phase();
    let matches_claim_generation =
        row.claimed_generation_id.as_deref() == Some(claim.generation_id());
    let matches_claim_epoch =
        row.claimed_generation_authority_epoch == claim.generation_authority_epoch;
    let must_quarantine = matches!(
        phase,
        GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid
    ) || !matches_claim_generation
        || !matches_claim_epoch;
    if must_quarantine {
        let _ = block_generation_binding_claim_identity_in(tx, claim, &row)?;
        return Ok(FencedBindingCurrent::NotCurrent);
    }
    if !matches_claim_generation || !fenced_claim_current_in(tx, claim)? {
        return Ok(FencedBindingCurrent::NotCurrent);
    }
    match phase {
        GenerationBindingPhase::Ephemeral | GenerationBindingPhase::Durable => {
            Ok(FencedBindingCurrent::Current(Box::new(row)))
        }
        GenerationBindingPhase::Unbound
        | GenerationBindingPhase::MissingAfterAttempt
        | GenerationBindingPhase::Invalid => Ok(FencedBindingCurrent::NotCurrent),
    }
}

// A one-shot, thread-local, default-off fault used to model "the reservation
// committed but the caller never received the result". It is compiled only into
// test builds, is not shared between threads, and never changes the release
// signature or control flow of the reserve path.
#[cfg(test)]
thread_local! {
    static POST_COMMIT_RESERVE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static POST_COMMIT_DELETE_WITNESS_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static POST_COMMIT_SUCCESS_FINALIZE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static POST_COMMIT_FAILURE_FINALIZE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static POST_COMMIT_ENQUEUE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn fail_next_reserve_after_commit_for_test() {
    POST_COMMIT_RESERVE_FAULT.with(|fault| fault.set(true));
}

#[cfg(test)]
fn take_post_commit_reserve_fault_for_test() -> bool {
    POST_COMMIT_RESERVE_FAULT.with(|fault| fault.replace(false))
}

#[cfg(test)]
fn fail_next_delete_witness_after_commit_for_test() {
    POST_COMMIT_DELETE_WITNESS_FAULT.with(|fault| fault.set(true));
}

#[cfg(test)]
fn take_post_commit_delete_witness_fault_for_test() -> bool {
    POST_COMMIT_DELETE_WITNESS_FAULT.with(|fault| fault.replace(false))
}

#[cfg(test)]
fn fail_next_success_finalize_after_commit_for_test() {
    POST_COMMIT_SUCCESS_FINALIZE_FAULT.with(|fault| fault.set(true));
}

#[cfg(test)]
fn take_post_commit_success_finalize_fault_for_test() -> bool {
    POST_COMMIT_SUCCESS_FINALIZE_FAULT.with(|fault| fault.replace(false))
}

#[cfg(test)]
fn fail_next_failure_finalize_after_commit_for_test() {
    POST_COMMIT_FAILURE_FINALIZE_FAULT.with(|fault| fault.set(true));
}

#[cfg(test)]
fn take_post_commit_failure_finalize_fault_for_test() -> bool {
    POST_COMMIT_FAILURE_FINALIZE_FAULT.with(|fault| fault.replace(false))
}

#[cfg(test)]
fn fail_next_enqueue_after_commit_for_test() {
    POST_COMMIT_ENQUEUE_FAULT.with(|fault| fault.set(true));
}

#[cfg(test)]
fn take_post_commit_enqueue_fault_for_test() -> bool {
    POST_COMMIT_ENQUEUE_FAULT.with(|fault| fault.replace(false))
}

/// The authoritative in-transaction Attempt reservation.
///
/// Every claim identity is re-verified here before anything is written: the
/// mutation, action, target revision/hash, generation, row lease owner/fence, both
/// runtime and row lease currency, `state='processing'`, `migration_disposition IS
/// NULL`, the claim's `fenced_claim_epoch`, and the relationship between the two
/// claim epochs.
fn reserve_fenced_attempt_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
) -> Result<FencedAttemptReservation, crate::storage::StorageError> {
    // Reuses the frozen binding/lease guard, so stale owner, stale runtime fence,
    // stale mutation, target mismatch, generation mismatch, expired lease, wrong
    // state, and migration isolation all fail closed exactly as before.
    let row = match inspect_fenced_generation_binding_in(tx, claim)? {
        FencedBindingCurrent::Current(row) => row,
        FencedBindingCurrent::NotCurrent => {
            return Ok(FencedAttemptReservation::LostLeaseOrSuperseded)
        }
    };
    // A claim describing a different claim epoch than the row currently carries is
    // stale by definition: a newer claim cycle already superseded it.
    if row.fenced_claim_epoch != claim.fenced_claim_epoch {
        return Ok(FencedAttemptReservation::LostLeaseOrSuperseded);
    }
    // Claim selection rejects this state, but reservation remains a defensive
    // production boundary for direct callers and races. It must never consume a
    // slot, clear evidence, or mint a capability for an unproven Delete.
    if is_delete_unknown_row(&row) {
        return Ok(FencedAttemptReservation::LostLeaseOrSuperseded);
    }

    match row.attempt_identity_phase() {
        AttemptIdentityPhase::Invalid => {
            block_generation_binding_claim_identity_in(tx, claim, &row)?;
            Ok(FencedAttemptReservation::LostLeaseOrSuperseded)
        }
        // A live claim always holds an epoch of at least 1, so this can only mean
        // the row was replaced by never-claimed state under us.
        AttemptIdentityPhase::NeverClaimed => Ok(FencedAttemptReservation::LostLeaseOrSuperseded),
        // The slot for this claim epoch is already reserved. Return the same
        // ordinal and an equivalent token, writing nothing at all — this is the
        // idempotent re-read that makes an unknown commit result recoverable, and
        // it is explicitly not a sixth slot even at the budget ceiling.
        AttemptIdentityPhase::ClaimMarked => Ok(FencedAttemptReservation::Reserved(Box::new(
            fenced_attempt_token(claim, row.attempt_count),
        ))),
        AttemptIdentityPhase::ClaimUnmarked => {
            if row.attempt_count >= MAX_VECTOR_SYNC_ATTEMPTS {
                // This claim cannot take a further slot. Converge the row instead of
                // leaving it to be claimed again.
                block_exhausted_attempt_budget_for_claim_in(tx, claim, &row)?;
                return Ok(FencedAttemptReservation::BudgetExhausted);
            }
            let changed = tx
                .execute(
                    &format!(
                        "UPDATE memory_vector_sync_outbox
                         SET attempt_count=attempt_count+1,
                             last_marked_claim_epoch=fenced_claim_epoch,
                             last_send_disposition=CASE WHEN desired_action='upsert' THEN 'possibly_sent' ELSE last_send_disposition END,
                             updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                         WHERE {GENERATION_BINDING_ROW_IDENTITY_WITH_ATTEMPT_EPOCHS}
                           AND attempt_count < {MAX_VECTOR_SYNC_ATTEMPTS}
                           AND last_marked_claim_epoch < fenced_claim_epoch"
                    ),
                    rusqlite::named_params! {
                        ":id": row.id,
                        ":desired_action": row.desired_action.as_str(),
                        ":mutation_sequence": row.mutation_sequence,
                        ":target_revision": row.target_revision,
                        ":target_content_hash": row.target_content_hash.as_deref(),
                        ":current_state": row.state.as_str(),
                        ":attempt_count": row.attempt_count,
                        ":claimed_generation_id": row.claimed_generation_id.as_deref(),
                        ":lease_owner": row.lease_owner.as_deref(),
                        ":lease_fence_epoch": row.lease_fence_epoch,
                        ":lease_expires_at": row.lease_expires_at.as_deref(),
                        ":fenced_claim_epoch": row.fenced_claim_epoch,
                        ":last_marked_claim_epoch": row.last_marked_claim_epoch,
                    },
                )
                .map_err(|_| single_event_error())?;
            if changed != 1 {
                // A concurrent writer won the CAS. No slot was consumed here.
                return Ok(FencedAttemptReservation::LostLeaseOrSuperseded);
            }
            let ordinal = row
                .attempt_count
                .checked_add(1)
                .ok_or_else(single_event_error)?;
            Ok(FencedAttemptReservation::Reserved(Box::new(
                fenced_attempt_token(claim, ordinal),
            )))
        }
    }
}

/// Builds the reservation proof from the claim identity plus the persisted
/// ordinal. There is no other constructor, so a token can only describe a slot
/// this transaction observed as reserved.
fn fenced_attempt_token(claim: &FencedVectorSyncClaim, ordinal: i64) -> FencedAttemptToken {
    FencedAttemptToken {
        outbox_id: claim.id,
        life_id: claim.life_id.clone(),
        memory_id: claim.memory_id.clone(),
        mutation_sequence: claim.mutation_sequence,
        action: claim.action,
        target_revision: claim.target_revision,
        target_content_hash: claim.target_content_hash.clone(),
        generation_id: claim.generation_id.clone(),
        generation_authority_epoch: claim.generation_authority_epoch,
        descriptor_hash: claim.descriptor_hash.clone(),
        dimension: claim.dimension,
        lease_owner: claim.lease_owner.clone(),
        fence_epoch: claim.fence_epoch,
        fenced_claim_epoch: claim.fenced_claim_epoch,
        attempt_ordinal: ordinal,
    }
}

/// Converges a row whose budget is spent while the current claim has not reserved
/// a slot. Attempt count, generation, mutation, target, and both epochs are
/// preserved; only state, lease, and schedule change.
fn block_exhausted_attempt_budget_for_claim_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
    row: &GenerationBindingRow,
) -> Result<InvariantBlockOutcome, crate::storage::StorageError> {
    if !binding_row_has_claim_processing_lease(row, claim) {
        return Ok(InvariantBlockOutcome::Superseded);
    }
    let error_code = exhausted_attempt_budget_error_code(row);
    let changed = tx
        .execute(
            &format!(
                "UPDATE memory_vector_sync_outbox
                 SET state='blocked', next_attempt_at=NULL, lease_owner=NULL,
                     lease_expires_at=NULL, lease_fence_epoch=NULL,
                     last_error_code=:last_error_code,
                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                 WHERE {GENERATION_BINDING_ROW_IDENTITY_WITH_ATTEMPT_EPOCHS}"
            ),
            rusqlite::named_params! {
                ":last_error_code": error_code,
                ":id": row.id,
                ":desired_action": row.desired_action.as_str(),
                ":mutation_sequence": row.mutation_sequence,
                ":target_revision": row.target_revision,
                ":target_content_hash": row.target_content_hash.as_deref(),
                ":current_state": row.state.as_str(),
                ":attempt_count": row.attempt_count,
                ":claimed_generation_id": row.claimed_generation_id.as_deref(),
                ":lease_owner": row.lease_owner.as_deref(),
                ":lease_fence_epoch": row.lease_fence_epoch,
                ":lease_expires_at": row.lease_expires_at.as_deref(),
                ":fenced_claim_epoch": row.fenced_claim_epoch,
                ":last_marked_claim_epoch": row.last_marked_claim_epoch,
            },
        )
        .map_err(|_| single_event_error())?;
    Ok(if changed == 1 {
        InvariantBlockOutcome::Applied
    } else {
        InvariantBlockOutcome::Superseded
    })
}

/// Verifies that a reservation still describes the current row, including that the
/// reserved ordinal is still the persisted `attempt_count` and that the row's
/// `last_marked_claim_epoch` is still the token's claim epoch.
fn fenced_attempt_token_current_in(
    tx: &Transaction<'_>,
    claim: &FencedVectorSyncClaim,
    token: &FencedAttemptToken,
) -> Result<bool, crate::storage::StorageError> {
    // The claim and the token must describe the same reservation.
    if token.outbox_id != claim.id
        || token.mutation_sequence != claim.mutation_sequence
        || token.action != claim.action
        || token.target_revision != claim.target_revision
        || token.target_content_hash.as_deref() != claim.target_content_hash()
        || token.generation_id != claim.generation_id
        || token.lease_owner != claim.lease_owner
        || token.fence_epoch != claim.fence_epoch
        || token.fenced_claim_epoch != claim.fenced_claim_epoch
    {
        return Ok(false);
    }
    // Reuses the pure dual-lease, generation, state, and migration guard. A
    // token check may reject malformed evidence, but it may never quarantine it.
    let row = match inspect_fenced_generation_binding_read_only_in(tx, claim)? {
        FencedBindingCurrent::Current(row) => row,
        FencedBindingCurrent::NotCurrent => return Ok(false),
    };
    Ok(row.fenced_claim_epoch == token.fenced_claim_epoch
        && row.last_marked_claim_epoch == token.fenced_claim_epoch
        && row.attempt_count == token.attempt_ordinal
        && matches!(
            row.attempt_identity_phase(),
            AttemptIdentityPhase::ClaimMarked
        ))
}

fn is_unknown_upsert_send(row: &GenerationBindingRow) -> bool {
    row.desired_action == "upsert"
        && has_unknown_external_send_evidence(
            row.last_send_disposition.as_deref(),
            row.last_error_code.as_deref(),
        )
}

fn is_delete_unknown_row(row: &GenerationBindingRow) -> bool {
    is_delete_unknown_evidence(
        row.desired_action.as_str(),
        row.last_send_disposition.as_deref(),
        row.last_error_code.as_deref(),
    )
}

fn has_unknown_external_send_evidence(
    last_send_disposition: Option<&str>,
    last_error_code: Option<&str>,
) -> bool {
    last_send_disposition == Some("possibly_sent")
        || last_error_code == Some("PROVIDER_RESULT_UNKNOWN")
}

/// Recovers only expired fenced processing rows. An upsert with a durable
/// attempt marker may already have crossed the provider boundary, so recovery
/// records the uncertainty instead of scheduling another cloud request.
fn recover_expired_fenced_processing_in(
    tx: &Transaction<'_>,
    retry_cutoff_millis: Option<i64>,
) -> Result<usize, crate::storage::StorageError> {
    let mut recovered = quarantine_generation_binding_invariants_in(tx)?;
    let recovery_now: String = tx
        .query_row(
            "SELECT COALESCE(
                strftime('%Y-%m-%dT%H:%M:%fZ', ?1 / 1000.0, 'unixepoch'),
                strftime('%Y-%m-%dT%H:%M:%fZ','now')
             )",
            params![retry_cutoff_millis],
            |row| row.get(0),
        )
        .map_err(|_| single_event_error())?;
    let rows = generation_binding_rows_in(tx, "state='processing'")?;
    for row in rows {
        let is_expired = row.lease_expires_at.as_deref().is_some_and(|expiry| {
            is_valid_utc_millis_timestamp(expiry) && expiry <= recovery_now.as_str()
        });
        match row.phase() {
            GenerationBindingPhase::Ephemeral if is_expired => {
                let changed = tx
                    .execute(
                        &format!(
                            "UPDATE memory_vector_sync_outbox
                             SET state='pending', next_attempt_at=NULL,
                                 lease_owner=NULL, lease_expires_at=NULL,
                                 lease_fence_epoch=NULL, claimed_generation_id=NULL, claimed_generation_authority_epoch=NULL,
                                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                             WHERE {GENERATION_BINDING_ROW_IDENTITY}
                               AND lease_expires_at <= :recovery_now"
                        ),
                        rusqlite::named_params! {
                            ":recovery_now": recovery_now.as_str(),
                            ":id": row.id,
                            ":desired_action": row.desired_action.as_str(),
                            ":mutation_sequence": row.mutation_sequence,
                            ":target_revision": row.target_revision,
                            ":target_content_hash": row.target_content_hash.as_deref(),
                            ":current_state": row.state.as_str(),
                            ":attempt_count": row.attempt_count,
                            ":claimed_generation_id": row.claimed_generation_id.as_deref(),
                            ":lease_owner": row.lease_owner.as_deref(),
                            ":lease_fence_epoch": row.lease_fence_epoch,
                            ":lease_expires_at": row.lease_expires_at.as_deref(),
                        },
                    )
                    .map_err(|_| single_event_error())?;
                recovered += usize::from(changed == 1);
            }
            GenerationBindingPhase::Durable if is_expired => {
                // Recovery never consumes or returns an Attempt. The two claim
                // epochs are the durable witness of whether the *current* claim
                // already reserved its slot, so they decide the outcome.
                let (next_state, error_assignment) = if is_unknown_upsert_send(&row) {
                    // Unknown Send outranks everything: an upsert that may already
                    // have crossed the provider boundary is never rescheduled, and
                    // stays visible to health as Unknown.
                    ("blocked", "last_error_code='PROVIDER_RESULT_UNKNOWN',")
                } else if is_delete_unknown_row(&row) {
                    // A Delete witness is never a replay permit. Preserve the
                    // original send/error evidence while releasing the expired
                    // lease into a stable non-claimable state.
                    ("blocked", "")
                } else {
                    match row.attempt_identity_phase() {
                        // The slot for this claim was reserved, so an external call
                        // may have happened under it.
                        AttemptIdentityPhase::ClaimMarked => {
                            match row.desired_action.as_str() {
                                "delete" if row.attempt_count >= MAX_VECTOR_SYNC_ATTEMPTS => {
                                    ("blocked", "last_error_code='MAX_ATTEMPTS',")
                                }
                                // A delete may return to ordinary work, but only a
                                // new claim and a new Attempt can actually re-issue
                                // it. This is not a late-delete safety claim and
                                // performs no compare-and-delete.
                                "delete" => ("pending", ""),
                                _ => ("blocked", "last_error_code='INTERNAL_INVARIANT',"),
                            }
                        }
                        // The current claim expired before reserving a slot, so no
                        // external call could have been made under it. The durable
                        // generation, the spent budget, the marked epoch, and the
                        // existing send/error evidence are all preserved.
                        AttemptIdentityPhase::ClaimUnmarked => ("pending", ""),
                        // A schema-13 row migrated while `processing` has both
                        // epochs at zero and therefore no schema-14 claim identity
                        // to reason about. Keep the pre-existing conservative
                        // legacy convergence.
                        AttemptIdentityPhase::NeverClaimed => {
                            match (
                                row.desired_action.as_str(),
                                row.last_send_disposition.as_deref(),
                            ) {
                                ("delete", None) => ("pending", ""),
                                _ => ("blocked", "last_error_code='INTERNAL_INVARIANT',"),
                            }
                        }
                        AttemptIdentityPhase::Invalid => {
                            ("blocked", "last_error_code='INTERNAL_INVARIANT',")
                        }
                    }
                };
                let changed = tx
                    .execute(
                        &format!(
                            "UPDATE memory_vector_sync_outbox
                             SET state='{next_state}', next_attempt_at=NULL,
                                 lease_owner=NULL, lease_expires_at=NULL,
                                 lease_fence_epoch=NULL,
                                 {error_assignment}
                                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                             WHERE {GENERATION_BINDING_ROW_IDENTITY}
                               AND lease_expires_at <= :recovery_now"
                        ),
                        rusqlite::named_params! {
                            ":recovery_now": recovery_now.as_str(),
                            ":id": row.id,
                            ":desired_action": row.desired_action.as_str(),
                            ":mutation_sequence": row.mutation_sequence,
                            ":target_revision": row.target_revision,
                            ":target_content_hash": row.target_content_hash.as_deref(),
                            ":current_state": row.state.as_str(),
                            ":attempt_count": row.attempt_count,
                            ":claimed_generation_id": row.claimed_generation_id.as_deref(),
                            ":lease_owner": row.lease_owner.as_deref(),
                            ":lease_fence_epoch": row.lease_fence_epoch,
                            ":lease_expires_at": row.lease_expires_at.as_deref(),
                        },
                    )
                    .map_err(|_| single_event_error())?;
                recovered += usize::from(changed == 1);
            }
            GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid => {
                if matches!(
                    block_generation_binding_scan_snapshot_in(tx, &row)?,
                    InvariantBlockOutcome::Applied
                ) {
                    recovered += 1;
                }
            }
            GenerationBindingPhase::Unbound
            | GenerationBindingPhase::Ephemeral
            | GenerationBindingPhase::Durable => {}
        }
    }
    Ok(recovered)
}

/// Quarantines a claim candidate whose Attempt identity is corrupt or whose claim
/// epoch can no longer advance. The CAS snapshot is the exact candidate the claim
/// observed, so a concurrent writer that already moved the row wins instead.
fn block_claim_candidate_identity_in(
    tx: &Transaction<'_>,
    candidate: &ClaimCandidate,
) -> Result<InvariantBlockOutcome, crate::storage::StorageError> {
    let changed = tx
        .execute(
            "UPDATE memory_vector_sync_outbox
             SET state='blocked', next_attempt_at=NULL, lease_owner=NULL,
                 lease_expires_at=NULL, lease_fence_epoch=NULL,
                 last_error_code='INTERNAL_INVARIANT',
                 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
             WHERE id=?1 AND state=?2 AND attempt_count=?3
               AND claimed_generation_id IS ?4 AND lease_owner IS ?5
               AND lease_fence_epoch IS ?6 AND lease_expires_at IS ?7
               AND fenced_claim_epoch=?8 AND last_marked_claim_epoch=?9
               AND migration_disposition IS NULL",
            params![
                candidate.id,
                candidate.state.as_str(),
                candidate.attempt_count,
                candidate.claimed_generation_id.as_deref(),
                candidate.lease_owner.as_deref(),
                candidate.lease_fence_epoch,
                candidate.lease_expires_at.as_deref(),
                candidate.fenced_claim_epoch,
                candidate.last_marked_claim_epoch,
            ],
        )
        .map_err(|_| single_event_error())?;
    Ok(if changed == 1 {
        InvariantBlockOutcome::Applied
    } else {
        InvariantBlockOutcome::Superseded
    })
}

#[allow(dead_code)]
fn fenced_claim_from_row(
    row: &Row<'_>,
    descriptor_hash: &str,
    dimension: usize,
) -> rusqlite::Result<FencedVectorSyncClaim> {
    let action: String = row.get(3)?;
    Ok(FencedVectorSyncClaim {
        id: row.get(0)?,
        life_id: row.get(1)?,
        memory_id: row.get(2)?,
        action: MemoryVectorSyncAction::parse(&action)
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        mutation_sequence: row.get(4)?,
        target_revision: row.get(5)?,
        target_content_hash: row.get(6)?,
        generation_id: row.get(7)?,
        generation_authority_epoch: row.get(8)?,
        descriptor_hash: descriptor_hash.to_owned(),
        dimension,
        lease_owner: row.get(9)?,
        fence_epoch: row.get(10)?,
        fenced_claim_epoch: row.get(11)?,
    })
}

#[allow(dead_code)]
fn single_event_error() -> crate::storage::StorageError {
    crate::storage::StorageError::new(
        "VECTOR_SYNC_UNAVAILABLE",
        "Vector synchronization is unavailable.",
        true,
    )
}

impl MemoryVectorSyncOutboxRepository for StorageService {
    fn enqueue(
        &self,
        request: EnqueueMemoryVectorSyncRequest,
    ) -> Result<MemoryVectorSyncJob, MemoryVectorSyncOutboxError> {
        let mut state = self.state().map_err(|_| outbox_error())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| outbox_error())?;
        enqueue_in_transaction(
            &transaction,
            &request.life_id,
            &request.memory_id,
            request.desired_action,
        )?;
        let job = load_job(&transaction, &request.life_id, &request.memory_id)?;
        transaction.commit().map_err(|_| outbox_error())?;
        #[cfg(test)]
        if take_post_commit_enqueue_fault_for_test() {
            return Err(outbox_error());
        }
        Ok(job)
    }

    fn claim_next(
        &self,
        request: ClaimMemoryVectorSyncRequest,
    ) -> Result<Option<MemoryVectorSyncJob>, MemoryVectorSyncOutboxError> {
        validate_worker(
            &request.life_id,
            &request.lease_owner,
            &request.lease_expires_at,
        )?;
        // D-9D1 events are generation-fenced.  The legacy, life-scoped claim
        // token cannot carry that authority and must never consume this outbox.
        if legacy_claims_are_disabled() {
            return Ok(None);
        }
        Err(outbox_error())
    }

    fn claim_next_with_lease(
        &self,
        request: ClaimMemoryVectorSyncLeaseRequest,
    ) -> Result<Option<MemoryVectorSyncJob>, MemoryVectorSyncOutboxError> {
        if request.lease_seconds == 0 || request.lease_seconds > 3_600 {
            return Err(outbox_error());
        }
        validate_worker(&request.life_id, &request.lease_owner, "calculated")?;
        // See claim_next: the legacy worker is deliberately failed closed.
        if legacy_claims_are_disabled() {
            return Ok(None);
        }
        Err(outbox_error())
    }

    fn mark_retry(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        next_attempt_at: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        self.set_claimed_state(
            life_id,
            memory_id,
            lease_owner,
            MemoryVectorSyncState::RetryWait,
            Some(next_attempt_at),
            error_code,
        )
    }

    fn mark_retry_after(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        delay_seconds: u32,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        validate_ids(life_id, memory_id)?;
        if delay_seconds == 0 || delay_seconds > 3_600 {
            return Err(outbox_error());
        }
        let state = self.state().map_err(|_| outbox_error())?;
        let changed = state
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET state = 'retry_wait',
                 next_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now', printf('+%d seconds', ?4)),
                 lease_owner = NULL, lease_expires_at = NULL, last_error_code = ?5,
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
                 WHERE life_id = ?1 AND memory_id = ?2 AND state = 'processing' AND lease_owner = ?3",
                params![
                    life_id,
                    memory_id,
                    lease_owner,
                    delay_seconds,
                    safe_error_code(error_code)
                ],
            )
            .map_err(|_| outbox_error())?;
        claimed_change(changed)
    }
    fn mark_blocked(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        self.set_claimed_state(
            life_id,
            memory_id,
            lease_owner,
            MemoryVectorSyncState::Blocked,
            None,
            error_code,
        )
    }
    fn mark_failed(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        self.set_claimed_state(
            life_id,
            memory_id,
            lease_owner,
            MemoryVectorSyncState::Failed,
            None,
            error_code,
        )
    }

    fn complete(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        validate_ids(life_id, memory_id)?;
        let state = self.state().map_err(|_| outbox_error())?;
        let changed = state.connection.execute("DELETE FROM memory_vector_sync_outbox WHERE life_id = ?1 AND memory_id = ?2 AND state = 'processing' AND lease_owner = ?3", params![life_id, memory_id, lease_owner]).map_err(|_| outbox_error())?;
        claimed_change(changed)
    }

    fn release_expired_leases(&self, life_id: &str) -> Result<usize, MemoryVectorSyncOutboxError> {
        if life_id.trim().is_empty() {
            return Err(outbox_error());
        }
        let state = self.state().map_err(|_| outbox_error())?;
        state.connection.execute("UPDATE memory_vector_sync_outbox SET state = 'pending', lease_owner = NULL, lease_expires_at = NULL, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE life_id = ?1 AND state = 'processing' AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')", params![life_id]).map_err(|_| outbox_error())
    }

    fn list(&self, life_id: &str) -> Result<Vec<MemoryVectorSyncJob>, MemoryVectorSyncOutboxError> {
        if life_id.trim().is_empty() {
            return Err(outbox_error());
        }
        let state = self.state().map_err(|_| outbox_error())?;
        let mut statement = state.connection.prepare(&format!("SELECT {COLUMNS} FROM memory_vector_sync_outbox WHERE life_id = ?1 ORDER BY created_at, id")).map_err(|_| outbox_error())?;
        let rows = statement
            .query_map(params![life_id], read_job)
            .map_err(|_| outbox_error())?;
        rows.map(|row| row.map_err(|_| outbox_error())?.try_into())
            .collect()
    }

    fn count(
        &self,
        life_id: &str,
        sync_state: MemoryVectorSyncState,
    ) -> Result<usize, MemoryVectorSyncOutboxError> {
        let state = self.state().map_err(|_| outbox_error())?;
        let count: i64 = state
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_sync_outbox WHERE life_id = ?1 AND state = ?2",
                params![life_id, sync_state.as_str()],
                |row| row.get(0),
            )
            .map_err(|_| outbox_error())?;
        usize::try_from(count).map_err(|_| outbox_error())
    }

    fn retry_failures(&self, life_id: &str) -> Result<usize, MemoryVectorSyncOutboxError> {
        if life_id.trim().is_empty() {
            return Err(outbox_error());
        }
        let mut state = self.state().map_err(|_| outbox_error())?;
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| outbox_error())?;
        let mut statement = transaction
            .prepare(&format!(
                "SELECT {GENERATION_BINDING_ROW_COLUMNS}
                 FROM memory_vector_sync_outbox
                 WHERE life_id=?1 AND migration_disposition IS NULL
                   AND state IN ('blocked','failed','retry_wait')
                 ORDER BY mutation_sequence ASC, id ASC"
            ))
            .map_err(|_| outbox_error())?;
        let rows = statement
            .query_map(params![life_id], generation_binding_row_from_row)
            .map_err(|_| outbox_error())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| outbox_error())?;
        drop(statement);

        let mut retried = 0;
        for row in rows {
            // An invalid Attempt identity is not retryable even when its
            // generation binding happens to look complete. In particular this
            // catches `attempt_count > MAX_VECTOR_SYNC_ATTEMPTS` in `failed` or
            // `blocked` rows, which ordinary candidate selection never sees.
            if matches!(row.attempt_identity_phase(), AttemptIdentityPhase::Invalid) {
                let outcome = block_generation_binding_scan_snapshot_in(&transaction, &row)
                    .map_err(|_| outbox_error())?;
                retried += usize::from(matches!(outcome, InvariantBlockOutcome::Applied));
                continue;
            }
            // A terminal budget is converged through the same authority used by
            // claim processing. Manual retry may never leave a count-five row
            // stranded in `failed`, nor turn it back into ordinary work.
            if row.attempt_count >= MAX_VECTOR_SYNC_ATTEMPTS {
                if row.state == "blocked" {
                    // It is already terminal. Invalid blocked rows were handled
                    // above, so this is not a retry and must not manufacture a
                    // second convergence or a changed return count.
                    continue;
                }
                let outcome = if matches!(
                    row.phase(),
                    GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid
                ) {
                    block_generation_binding_scan_snapshot_in(&transaction, &row)
                        .map_err(|_| outbox_error())?
                } else {
                    converge_exhausted_attempt_budget_row_in(&transaction, &row)
                        .map_err(|_| outbox_error())?
                };
                retried += usize::from(matches!(outcome, InvariantBlockOutcome::Applied));
                continue;
            }
            match row.phase() {
                GenerationBindingPhase::MissingAfterAttempt | GenerationBindingPhase::Invalid => {
                    let outcome = block_generation_binding_scan_snapshot_in(&transaction, &row)
                        .map_err(|_| outbox_error())?;
                    retried += usize::from(matches!(outcome, InvariantBlockOutcome::Applied));
                }
                GenerationBindingPhase::Unbound | GenerationBindingPhase::Durable => {
                    if is_unknown_upsert_send(&row)
                        || is_delete_unknown_row(&row)
                        || row.last_error_code.as_deref() == Some("INTERNAL_INVARIANT")
                    {
                        continue;
                    }
                    // Manual retry may not reduce or reset the count, clear a
                    // durable generation, or reset either claim epoch.
                    let changed = transaction
                        .execute(
                            &format!(
                                "UPDATE memory_vector_sync_outbox
                                 SET state='pending', next_attempt_at=NULL,
                                     lease_owner=NULL, lease_expires_at=NULL,
                                     lease_fence_epoch=NULL, last_error_code=NULL,
                                     updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
                                 WHERE life_id=:life_id
                                   AND {GENERATION_BINDING_ROW_IDENTITY}"
                            ),
                            rusqlite::named_params! {
                                ":life_id": life_id,
                                ":id": row.id,
                                ":desired_action": row.desired_action.as_str(),
                                ":mutation_sequence": row.mutation_sequence,
                                ":target_revision": row.target_revision,
                                ":target_content_hash": row.target_content_hash.as_deref(),
                                ":current_state": row.state.as_str(),
                                ":attempt_count": row.attempt_count,
                                ":claimed_generation_id": row.claimed_generation_id.as_deref(),
                                ":lease_owner": row.lease_owner.as_deref(),
                                ":lease_fence_epoch": row.lease_fence_epoch,
                                ":lease_expires_at": row.lease_expires_at.as_deref(),
                            },
                        )
                        .map_err(|_| outbox_error())?;
                    retried += usize::from(changed == 1);
                }
                GenerationBindingPhase::Ephemeral => {
                    // A valid Ephemeral row is processing-only and therefore
                    // cannot be reached by the manual retry state filter.
                }
            }
        }
        transaction.commit().map_err(|_| outbox_error())?;
        Ok(retried)
    }
}

impl StorageService {
    fn set_claimed_state(
        &self,
        life_id: &str,
        memory_id: &str,
        lease_owner: &str,
        sync_state: MemoryVectorSyncState,
        next_attempt_at: Option<&str>,
        error_code: &str,
    ) -> Result<(), MemoryVectorSyncOutboxError> {
        validate_ids(life_id, memory_id)?;
        let state = self.state().map_err(|_| outbox_error())?;
        let changed = state.connection.execute("UPDATE memory_vector_sync_outbox SET state = ?4, next_attempt_at = ?5, lease_owner = NULL, lease_expires_at = NULL, last_error_code = ?6, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE life_id = ?1 AND memory_id = ?2 AND state = 'processing' AND lease_owner = ?3", params![life_id, memory_id, lease_owner, sync_state.as_str(), next_attempt_at, safe_error_code(error_code)]).map_err(|_| outbox_error())?;
        claimed_change(changed)
    }
}

struct StoredJob {
    id: i64,
    life_id: String,
    memory_id: String,
    action: String,
    state: String,
    attempt_count: i64,
    next_attempt_at: Option<String>,
    lease_owner: Option<String>,
    lease_expires_at: Option<String>,
    last_error_code: Option<String>,
    created_at: String,
    updated_at: String,
}
impl TryFrom<StoredJob> for MemoryVectorSyncJob {
    type Error = MemoryVectorSyncOutboxError;
    fn try_from(value: StoredJob) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            life_id: value.life_id,
            memory_id: value.memory_id,
            desired_action: MemoryVectorSyncAction::parse(&value.action)?,
            state: MemoryVectorSyncState::parse(&value.state)?,
            attempt_count: u32::try_from(value.attempt_count).map_err(|_| outbox_error())?,
            next_attempt_at: value.next_attempt_at,
            lease_owner: value.lease_owner,
            lease_expires_at: value.lease_expires_at,
            last_error_code: value.last_error_code,
            created_at: value.created_at,
            updated_at: value.updated_at,
        })
    }
}
fn read_job(row: &Row<'_>) -> rusqlite::Result<StoredJob> {
    Ok(StoredJob {
        id: row.get(0)?,
        life_id: row.get(1)?,
        memory_id: row.get(2)?,
        action: row.get(3)?,
        state: row.get(4)?,
        attempt_count: row.get(5)?,
        next_attempt_at: row.get(6)?,
        lease_owner: row.get(7)?,
        lease_expires_at: row.get(8)?,
        last_error_code: row.get(9)?,
        created_at: row.get(10)?,
        updated_at: row.get(11)?,
    })
}
fn load_job(
    connection: &Connection,
    life_id: &str,
    memory_id: &str,
) -> Result<MemoryVectorSyncJob, MemoryVectorSyncOutboxError> {
    connection.query_row(&format!("SELECT {COLUMNS} FROM memory_vector_sync_outbox WHERE life_id = ?1 AND memory_id = ?2"), params![life_id, memory_id], read_job).optional().map_err(|_| outbox_error())?.ok_or_else(|| MemoryVectorSyncOutboxError::new(MemoryVectorSyncOutboxErrorCode::SyncJobNotFound))?.try_into()
}
fn validate_ids(life_id: &str, memory_id: &str) -> Result<(), MemoryVectorSyncOutboxError> {
    if life_id.trim().is_empty() || memory_id.trim().is_empty() {
        Err(outbox_error())
    } else {
        Ok(())
    }
}
fn validate_worker(
    life_id: &str,
    owner: &str,
    expires: &str,
) -> Result<(), MemoryVectorSyncOutboxError> {
    if life_id.trim().is_empty()
        || owner.trim().is_empty()
        || owner.chars().count() > 128
        || expires.trim().is_empty()
    {
        Err(outbox_error())
    } else {
        Ok(())
    }
}
fn safe_error_code(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || *character == '_'
        })
        .take(64)
        .collect()
}
fn claimed_change(changed: usize) -> Result<(), MemoryVectorSyncOutboxError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(MemoryVectorSyncOutboxError::new(
            MemoryVectorSyncOutboxErrorCode::SyncJobLeaseConflict,
        ))
    }
}
fn outbox_error() -> MemoryVectorSyncOutboxError {
    MemoryVectorSyncOutboxError::new(MemoryVectorSyncOutboxErrorCode::OutboxUnavailable)
}

fn legacy_claims_are_disabled() -> bool {
    // Migration 012 events are only consumable through the fenced, single
    // event API. The old life-scoped claim tokens lack generation and runtime
    // fence authority, so this remains closed in every build, including tests.
    true
}

#[cfg(test)]
pub struct ExistingGenerationBindingReadObservationToken {
    total_changes_before: u64,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExistingGenerationBindingObservationResult {
    Unchanged,
    Mutated,
}

#[cfg(test)]
impl StorageService {
    pub fn begin_existing_generation_binding_read_observation_for_test(
        &self,
    ) -> Result<ExistingGenerationBindingReadObservationToken, crate::storage::StorageError> {
        let state = self.state()?;
        let total_changes_before = state.connection.total_changes();
        Ok(ExistingGenerationBindingReadObservationToken {
            total_changes_before,
        })
    }

    pub fn finish_existing_generation_binding_read_observation_for_test(
        &self,
        token: ExistingGenerationBindingReadObservationToken,
    ) -> Result<ExistingGenerationBindingObservationResult, crate::storage::StorageError> {
        let state = self.state()?;
        let total_changes_after = state.connection.total_changes();
        if total_changes_after == token.total_changes_before {
            Ok(ExistingGenerationBindingObservationResult::Unchanged)
        } else {
            Ok(ExistingGenerationBindingObservationResult::Mutated)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        memory::{
            revisions::{
                DeleteMemoryPermanentlyRequest, MemoryRevisionService, UpdateConfirmedMemoryRequest,
            },
            ConfirmMemoryRequest, CreateMemoryCandidateRequest, MemoryKind, MemoryService,
            MemorySourceType,
        },
        storage::{LifeIdentityRecord, PersonaTemplateRecord},
    };
    use std::{
        fs,
        path::PathBuf,
        sync::{mpsc, Arc, Barrier},
        thread,
    };

    struct TestRoot(PathBuf);
    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir()
                .join(format!("vector-outbox-{}", super::super::unique_suffix()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn storage() -> (TestRoot, StorageService) {
        let root = TestRoot::new();
        let storage = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        storage
            .save_persona(PersonaTemplateRecord {
                id: "persona".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{\"id\":\"persona\"}".into(),
            })
            .unwrap();
        storage
            .save_life(LifeIdentityRecord {
                id: "life".into(),
                name: "Life".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                version: 1,
                body_id: "body".into(),
                persona_id: "persona".into(),
                persona_version: 1,
            })
            .unwrap();
        (root, storage)
    }
    fn candidate(storage: &StorageService, sensitive: bool) -> crate::memory::MemoryRecord {
        MemoryService::new(storage)
            .create_candidate(CreateMemoryCandidateRequest {
                life_id: "life".into(),
                kind: MemoryKind::Fact,
                content: "fixture memory".into(),
                summary: None,
                source_type: MemorySourceType::Manual,
                source_ref: None,
                source_created_at: "2026-01-01T00:00:00Z".into(),
                importance: 0.5,
                confidence: 0.5,
                is_sensitive: sensitive,
            })
            .unwrap()
    }

    /// Reads the two schema-14 claim epochs straight from SQLite, so Attempt
    /// identity is always asserted against persisted state rather than a mock.
    fn attempt_epochs(storage: &StorageService, memory_id: &str) -> (i64, i64) {
        storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT fenced_claim_epoch, last_marked_claim_epoch
                 FROM memory_vector_sync_outbox WHERE memory_id=?1",
                params![memory_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap()
    }

    /// Establishes one confirmed upsert row plus a building generation, and returns
    /// the first ordinary claim. Used by the Attempt-budget tests so each starts
    /// from a real claimed row rather than hand-built state.
    fn claimed_upsert(storage: &StorageService) -> FencedVectorSyncClaim {
        confirmed(storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap()
    }

    fn reserve_token(
        storage: &StorageService,
        claim: &FencedVectorSyncClaim,
    ) -> FencedAttemptToken {
        storage.test_reserve_fenced_attempt_token(claim).unwrap()
    }

    /// Test-only structural copy. The production claim deliberately remains
    /// non-Clone; concurrent tests need two independently-owned stale/current
    /// views of the same persisted claim identity.
    fn copy_fenced_claim_for_test(claim: &FencedVectorSyncClaim) -> FencedVectorSyncClaim {
        FencedVectorSyncClaim {
            id: claim.id,
            life_id: claim.life_id.clone(),
            memory_id: claim.memory_id.clone(),
            action: claim.action,
            mutation_sequence: claim.mutation_sequence,
            target_revision: claim.target_revision,
            target_content_hash: claim.target_content_hash.clone(),
            generation_id: claim.generation_id.clone(),
            generation_authority_epoch: claim.generation_authority_epoch,
            descriptor_hash: claim.descriptor_hash.clone(),
            dimension: claim.dimension,
            lease_owner: claim.lease_owner.clone(),
            fence_epoch: claim.fence_epoch,
            fenced_claim_epoch: claim.fenced_claim_epoch,
        }
    }

    fn assert_fenced_attempt_token_guard_is_read_only(
        label: &str,
        mutate: impl FnOnce(&StorageService, &FencedVectorSyncClaim),
    ) {
        let (_root, storage) = storage();
        let claim = claimed_upsert(&storage);
        let token = reserve_token(&storage, &claim);
        mutate(&storage, &claim);

        let before = storage
            .test_get_outbox_snapshot_detailed(claim.life_id(), claim.memory_id())
            .unwrap();
        assert!(
            !storage
                .validate_fenced_attempt_token_current(&token)
                .unwrap(),
            "{label}: malformed or stale evidence is never current"
        );
        let after = storage
            .test_get_outbox_snapshot_detailed(claim.life_id(), claim.memory_id())
            .unwrap();
        assert_eq!(
            after, before,
            "{label}: the Token Guard must perform no persistent mutation"
        );
    }

    /// Produces two claims for the same mutation, target, generation, owner, and
    /// runtime fence. Only the row claim epoch differs. The first claim is released
    /// through the ordinary failure path so the second is a real, durable re-claim.
    fn same_owner_same_fence_epoch_pair(
        storage: &StorageService,
    ) -> (FencedVectorSyncClaim, FencedVectorSyncClaim) {
        let old_claim = claimed_upsert(storage);
        let old_token = reserve_token(storage, &old_claim);
        assert_eq!(old_token.attempt_ordinal(), 1);
        assert_eq!(
            storage
                .finalize_fenced_vector_failure(
                    &old_token,
                    "PROVIDER_UNAVAILABLE",
                    FencedFailureDecision::RetryAfter { delay_millis: 1 },
                    Some("definitely_not_sent"),
                    0,
                    0,
                )
                .unwrap(),
            FencedFailureFinalizeResult::RetryScheduled {
                next_attempt_at_millis: 1
            }
        );
        let current_claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .expect("the released durable binding may be claimed again");
        assert_eq!(
            current_claim.mutation_sequence(),
            old_claim.mutation_sequence()
        );
        assert_eq!(current_claim.action(), old_claim.action());
        assert_eq!(current_claim.target_revision(), old_claim.target_revision());
        assert_eq!(
            current_claim.target_content_hash(),
            old_claim.target_content_hash()
        );
        assert_eq!(current_claim.generation_id(), old_claim.generation_id());
        assert_eq!(current_claim.lease_owner(), old_claim.lease_owner());
        assert_eq!(current_claim.fence_epoch(), old_claim.fence_epoch());
        assert_eq!(
            current_claim.fenced_claim_epoch(),
            old_claim.fenced_claim_epoch() + 1
        );
        (old_claim, current_claim)
    }

    /// Uses four real reserve/finalize/reclaim cycles to reach a valid live claim
    /// whose next reservation is the fifth and final slot. No fixture fabricates
    /// the budget or epoch relationship.
    fn claim_before_final_attempt_slot(storage: &StorageService) -> FencedVectorSyncClaim {
        let mut claim = claimed_upsert(storage);
        for expected_ordinal in 1..MAX_VECTOR_SYNC_ATTEMPTS {
            let token = reserve_token(storage, &claim);
            assert_eq!(token.attempt_ordinal(), expected_ordinal);
            assert_eq!(
                storage
                    .finalize_fenced_vector_failure(
                        &token,
                        "PROVIDER_UNAVAILABLE",
                        FencedFailureDecision::RetryAfter { delay_millis: 1 },
                        Some("definitely_not_sent"),
                        0,
                        0,
                    )
                    .unwrap(),
                FencedFailureFinalizeResult::RetryScheduled {
                    next_attempt_at_millis: 1
                }
            );
            claim = storage
                .claim_one_fenced_vector_sync_with_retry_cutoff(
                    "generation-a",
                    "descriptor-a",
                    2,
                    "worker-a",
                    Some(60_000),
                )
                .unwrap()
                .expect("each of the first four slots can be followed by a fresh claim");
        }
        claim
    }

    fn confirmed(storage: &StorageService, sensitive: bool) -> crate::memory::MemoryRecord {
        super::super::test_support::insert_confirmed_memory_fixture(
            storage,
            "life",
            "fact",
            "fixture memory",
            None,
            0.5,
            0.5,
            sensitive,
            !sensitive,
        )
    }

    #[test]
    fn migration_schema_is_safe_and_candidate_does_not_enqueue() {
        let (_root, storage) = storage();
        candidate(&storage, false);
        assert!(storage.list("life").unwrap().is_empty());
        let state = storage.state().unwrap();
        let columns: Vec<String> = state
            .connection
            .prepare("PRAGMA table_info(memory_vector_sync_outbox)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        for forbidden in ["content", "summary", "vector", "api_key"] {
            assert!(!columns.iter().any(|column| column == forbidden));
        }
        let version: i64 = state
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 16);
    }

    #[test]
    fn migration_003_upgrades_to_004_and_reopen_is_idempotent() {
        let root = TestRoot::new();
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(super::super::DATABASE_FILE_NAME);
        let connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );",
            )
            .unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(3) {
            connection.execute_batch(sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-01-01T00:00:00Z')",
                    params![version, name],
                )
                .unwrap();
        }
        drop(connection);

        let storage = StorageService::initialize_with_roots(data_root.clone(), None).unwrap();
        let version: i64 = storage
            .state()
            .unwrap()
            .connection
            .query_row("SELECT MAX(version) FROM schema_migration", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(version, 16);
        drop(storage);

        let reopened = StorageService::initialize_with_roots(data_root, None).unwrap();
        let migration_count: i64 = reopened
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM schema_migration WHERE version = 4",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(migration_count, 1);
    }

    #[test]
    fn migration_012_quarantines_legacy_upserts_and_releases_only_processing_deletes() {
        let root = TestRoot::new();
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(super::super::DATABASE_FILE_NAME);
        let connection = Connection::open(&database_path).unwrap();
        connection.execute_batch("CREATE TABLE schema_migration (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);").unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(11) {
            connection.execute_batch(sql).unwrap();
            connection.execute("INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, ?2, '2026-01-01T00:00:00Z')", params![version, name]).unwrap();
        }
        connection.execute("INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at) VALUES ('life', 'legacy-upsert', 'upsert', 'processing', 2, 'OLD_CODE', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')", []).unwrap();
        connection.execute("INSERT INTO memory_vector_sync_outbox (life_id, memory_id, desired_action, state, attempt_count, last_error_code, created_at, updated_at) VALUES ('life', 'legacy-delete', 'delete', 'processing', 3, 'DELETE_CODE', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')", []).unwrap();
        drop(connection);
        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();
        let upsert: (String, Option<String>, Option<i64>, Option<String>, i64, String) = state.connection.query_row(
            "SELECT state, migration_disposition, target_revision, target_content_hash, attempt_count, last_error_code FROM memory_vector_sync_outbox WHERE memory_id='legacy-upsert'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?)),
        ).unwrap();
        assert_eq!(
            upsert,
            (
                "blocked".into(),
                Some("legacy_upsert_rebuild_required".into()),
                None,
                None,
                2,
                "OLD_CODE".into()
            )
        );
        let delete: (String, Option<String>, i64, String) = state.connection.query_row(
            "SELECT state, migration_disposition, attempt_count, last_error_code FROM memory_vector_sync_outbox WHERE memory_id='legacy-delete'", [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert_eq!(
            delete,
            (
                "failed".into(),
                Some("legacy_upsert_rebuild_required".into()),
                3,
                "DELETE_CODE".into(),
            )
        );
        let clock: i64 = state
            .connection
            .query_row(
                "SELECT last_sequence FROM memory_vector_sync_mutation_clock WHERE singleton=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let max_sequence: i64 = state
            .connection
            .query_row(
                "SELECT MAX(mutation_sequence) FROM memory_vector_sync_outbox",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(clock >= max_sequence);
    }

    #[test]
    fn migration_012_failure_rolls_back_schema_and_outbox_mutations() {
        let root = TestRoot::new();
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(super::super::DATABASE_FILE_NAME);
        let mut connection = Connection::open(&database_path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migration (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    applied_at TEXT NOT NULL
                );",
            )
            .unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(11) {
            connection.execute_batch(sql).unwrap();
            connection
                .execute(
                    "INSERT INTO schema_migration (version, name, applied_at)
                     VALUES (?1, ?2, '2026-01-01T00:00:00Z')",
                    params![version, name],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO memory_vector_sync_outbox
                 (id, life_id, memory_id, desired_action, state, attempt_count, last_error_code,
                  next_attempt_at, created_at, updated_at)
                 VALUES (17, 'life', 'rollback-row', 'upsert', 'retry_wait', 4, 'OLD_CODE',
                         '2026-01-02T00:00:00Z', '2026-01-01T00:00:00Z', '2026-01-03T00:00:00Z')",
                [],
            )
            .unwrap();
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        transaction
            .execute_batch(super::super::MIGRATIONS[11].2)
            .unwrap();
        assert!(transaction
            .execute_batch("SELECT intentionally_invalid_sql")
            .is_err());
        transaction.rollback().unwrap();

        let generation_table: Option<String> = connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='memory_vector_generation'",
                [],
                |row| row.get(0),
            )
            .optional()
            .unwrap();
        assert_eq!(generation_table, None);
        let row: (i64, String, i64, String, Option<String>, String, String) = connection
            .query_row(
                "SELECT id, state, attempt_count, last_error_code, next_attempt_at, created_at, updated_at
                 FROM memory_vector_sync_outbox WHERE memory_id='rollback-row'",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            row,
            (
                17,
                "retry_wait".into(),
                4,
                "OLD_CODE".into(),
                Some("2026-01-02T00:00:00Z".into()),
                "2026-01-01T00:00:00Z".into(),
                "2026-01-03T00:00:00Z".into(),
            )
        );
        let columns: Vec<String> = connection
            .prepare("PRAGMA table_info(memory_vector_sync_outbox)")
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(!columns.iter().any(|column| column == "mutation_sequence"));
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn migration_012_preserves_non_contiguous_rowids_and_maps_all_legacy_delete_states() {
        let root = TestRoot::new();
        let data_root = root.0.join("data");
        fs::create_dir_all(&data_root).unwrap();
        let database_path = data_root.join(super::super::DATABASE_FILE_NAME);
        let connection = Connection::open(&database_path).unwrap();
        connection.execute_batch("CREATE TABLE schema_migration (version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL);").unwrap();
        for (version, name, sql) in super::super::MIGRATIONS.iter().take(11) {
            connection.execute_batch(sql).unwrap();
            connection.execute("INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, ?2, '2026-01-01T00:00:00Z')", params![version, name]).unwrap();
        }
        let fixtures = [
            (2_i64, "upsert", "pending"),
            (7, "delete", "pending"),
            (19, "delete", "processing"),
            (41, "delete", "retry_wait"),
            (103, "delete", "blocked"),
            (211, "delete", "failed"),
        ];
        for (index, (id, action, state)) in fixtures.iter().enumerate() {
            connection
                .execute(
                    "INSERT INTO memory_vector_sync_outbox
                 (id, life_id, memory_id, desired_action, state, attempt_count, last_error_code,
                  next_attempt_at, lease_owner, lease_expires_at, created_at, updated_at)
                 VALUES (?1, 'life', ?2, ?3, ?4, ?5, ?6, ?7, 'legacy-owner',
                         '2099-01-01T00:00:00Z', ?8, ?9)",
                    params![
                        id,
                        format!("legacy-{id}"),
                        action,
                        state,
                        (index + 1) as i64,
                        format!("OLD_{id}"),
                        format!("2026-01-{:02}T00:00:00Z", index + 1),
                        format!("2025-12-{:02}T00:00:00Z", index + 1),
                        format!("2026-02-{:02}T00:00:00Z", index + 1),
                    ],
                )
                .unwrap();
        }
        let before: Vec<(i64, i64, String, String, String, i64, String, Option<String>, String, String)> = connection.prepare(
            "SELECT rowid, id, life_id, memory_id, desired_action, attempt_count, last_error_code, next_attempt_at, created_at, updated_at FROM memory_vector_sync_outbox ORDER BY id"
        ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?))).unwrap().map(Result::unwrap).collect();
        drop(connection);

        let storage = StorageService::initialize_with_roots(data_root, None).unwrap();
        let state = storage.state().unwrap();
        let after: Vec<(i64, i64, String, String, String, String, i64, String, Option<String>, String, Option<String>, Option<i64>, Option<String>, Option<String>, Option<String>, Option<i64>, Option<String>)> = state.connection.prepare(
            "SELECT rowid, id, life_id, memory_id, desired_action, state, attempt_count, last_error_code, next_attempt_at, created_at, migration_disposition, target_revision, target_content_hash, lease_owner, lease_expires_at, lease_fence_epoch, last_send_disposition FROM memory_vector_sync_outbox ORDER BY id"
        ).unwrap().query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?, row.get(10)?, row.get(11)?, row.get(12)?, row.get(13)?, row.get(14)?, row.get(15)?, row.get(16)?))).unwrap().map(Result::unwrap).collect();
        assert_eq!(before.len(), after.len());
        for (index, row) in after.iter().enumerate() {
            let original = &before[index];
            assert_eq!(
                (row.0, row.1, &row.2, &row.3, &row.4, row.6, &row.7, &row.9),
                (
                    original.0,
                    original.1,
                    &original.2,
                    &original.3,
                    &original.4,
                    original.5,
                    &original.6,
                    &original.8
                )
            );
            assert_eq!(row.13, None);
            assert_eq!(row.14, None);
            assert_eq!(row.15, None);
            assert_eq!(row.16, None);
            let h1_b_isolated_delete =
                row.4 == "delete" && matches!(fixtures[index].2, "pending" | "processing");
            if row.4 == "upsert" {
                assert_eq!(row.5, "blocked");
                assert_eq!(row.10.as_deref(), Some("legacy_upsert_rebuild_required"));
                assert_eq!(row.8, original.7);
            } else if h1_b_isolated_delete {
                assert_eq!(row.5, "failed");
                assert_eq!(row.10.as_deref(), Some("legacy_upsert_rebuild_required"));
                assert_eq!(row.8, None);
                assert_eq!(row.11, None);
                assert_eq!(row.12, None);
            } else {
                assert_eq!(row.5, fixtures[index].2);
                assert_eq!(row.10, None);
                assert_eq!(row.11, None);
                assert_eq!(row.12, None);
                assert_eq!(row.8, original.7);
            }
        }
    }

    #[test]
    fn post_012_mutation_replaces_legacy_quarantine_with_bound_target() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        let state = storage.state().unwrap();
        let row: (i64, Option<i64>, Option<String>, Option<String>) = state.connection.query_row(
            "SELECT mutation_sequence, target_revision, target_content_hash, migration_disposition FROM memory_vector_sync_outbox WHERE memory_id=?1", params![record.id], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).unwrap();
        assert!(row.0 > 0);
        assert_eq!(row.1, Some(1));
        assert!(row.2.is_some());
        assert_eq!(row.3, None);
    }

    #[test]
    fn confirmed_fixture_enqueues_and_delete_preserves_folded_job() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        let jobs = storage.list("life").unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].desired_action, MemoryVectorSyncAction::Upsert);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        assert_eq!(storage.list("life").unwrap().len(), 1);
        MemoryRevisionService::new(&storage)
            .delete_permanently(DeleteMemoryPermanentlyRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                expected_revision: 1,
            })
            .unwrap();
        let jobs = storage.list("life").unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].desired_action, MemoryVectorSyncAction::Delete);
        assert!(<StorageService as crate::memory::MemoryRepository>::get(
            &storage, "life", &record.id
        )
        .is_err());
    }

    #[test]
    fn sensitive_confirmation_is_unavailable_and_never_enqueues_upsert() {
        let (_root, storage) = storage();
        let record = candidate(&storage, true);
        let error = MemoryService::new(&storage)
            .confirm(ConfirmMemoryRequest {
                life_id: "life".into(),
                memory_id: record.id,
                user_confirmed: true,
                sensitive_consent: true,
            })
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_CONFIRMATION_UNAVAILABLE");
        assert!(storage.list("life").unwrap().is_empty());
    }

    #[test]
    fn confirm_is_unavailable_and_does_not_modify_candidate() {
        let (_root, storage) = storage();
        let record = candidate(&storage, false);
        let error = MemoryService::new(&storage)
            .confirm(ConfirmMemoryRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_CONFIRMATION_UNAVAILABLE");
        let authoritative =
            <StorageService as crate::memory::MemoryRepository>::get(&storage, "life", &record.id)
                .unwrap();
        assert_eq!(authoritative.status, crate::memory::MemoryStatus::Candidate);
        assert!(storage.list("life").unwrap().is_empty());
    }

    #[test]
    fn legacy_claim_apis_fail_closed_for_post_012_outbox() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let before = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert!(storage
            .claim_next(ClaimMemoryVectorSyncRequest {
                life_id: "life".into(),
                lease_owner: "worker-a".into(),
                lease_expires_at: "2999-01-01T00:00:00.000Z".into(),
            })
            .unwrap()
            .is_none());
        assert!(storage
            .claim_next_with_lease(ClaimMemoryVectorSyncLeaseRequest {
                life_id: "life".into(),
                lease_owner: "worker-b".into(),
                lease_seconds: 120,
            })
            .unwrap()
            .is_none());
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.memory_id, record.id);
        assert_eq!(job.state, MemoryVectorSyncState::Pending);
        assert_eq!(job.attempt_count, 0);
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap(),
            before,
            "legacy claim APIs must not mutate state, Attempt, epoch, lease, or evidence"
        );
    }

    #[test]
    fn enqueue_rejects_a_memory_owned_by_another_life() {
        let (_root, storage) = storage();
        storage
            .save_life(LifeIdentityRecord {
                id: "other-life".into(),
                name: "Other Life".into(),
                created_at: "2026-01-01T00:00:00Z".into(),
                version: 1,
                body_id: "other-body".into(),
                persona_id: "persona".into(),
                persona_version: 1,
            })
            .unwrap();
        let other = super::super::test_support::insert_confirmed_memory_fixture(
            &storage,
            "other-life",
            "fact",
            "other fixture",
            None,
            0.5,
            0.5,
            false,
            false,
        );

        let error = storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: other.id,
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap_err();

        assert_eq!(
            error.code,
            MemoryVectorSyncOutboxErrorCode::SyncJobLifeMismatch
        );
        assert!(storage.list("life").unwrap().is_empty());
        assert!(storage.list("other-life").unwrap().is_empty());
    }

    #[test]
    fn concurrent_claims_obtain_the_job_at_most_once() {
        let (root, first_store) = storage();
        let _memory = confirmed(&first_store, false);
        let second_store =
            StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let claim = |store: StorageService, owner: &'static str, barrier: Arc<Barrier>| {
            thread::spawn(move || {
                barrier.wait();
                store.claim_next(ClaimMemoryVectorSyncRequest {
                    life_id: "life".into(),
                    lease_owner: owner.into(),
                    lease_expires_at: "2999-01-01T00:00:00.000Z".into(),
                })
            })
        };
        let first = claim(first_store, "worker-a", Arc::clone(&barrier));
        let second = claim(second_store, "worker-b", barrier);
        let obtained = [first.join().unwrap(), second.join().unwrap()]
            .into_iter()
            .filter(|result| matches!(result, Ok(Some(_))))
            .count();
        assert_eq!(obtained, 0);
    }

    #[test]
    fn same_owner_renewal_keeps_fence_and_expired_takeover_advances_it() {
        let (_root, storage) = storage();
        let mut state = storage.state().unwrap();
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let first = acquire_runtime_lease(&transaction, "worker-a").unwrap();
        transaction.commit().unwrap();

        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let renewed = acquire_runtime_lease(&transaction, "worker-a").unwrap();
        assert_eq!(renewed, first);
        transaction.commit().unwrap();

        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_runtime_lease SET expires_at='2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
        let transaction = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        let takeover = acquire_runtime_lease(&transaction, "worker-b").unwrap();
        assert_eq!(takeover, first + 1);
    }

    #[test]
    fn fenced_failure_finalize_uses_cutoff_base_and_returns_durable_state() {
        let (_root, storage) = storage();
        confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        let token = reserve_token(&storage, &claim);
        assert_eq!(
            storage
                .finalize_fenced_vector_failure(
                    &token,
                    "RATE_LIMITED",
                    FencedFailureDecision::RetryAfter {
                        delay_millis: 30_000,
                    },
                    Some("definitely_not_sent"),
                    90_000,
                    100_000,
                )
                .unwrap(),
            FencedFailureFinalizeResult::RetryScheduled {
                next_attempt_at_millis: 130_000,
            }
        );
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::RetryWait);
        assert_eq!(job.attempt_count, 1);
        assert_eq!(job.last_error_code.as_deref(), Some("RATE_LIMITED"));
        assert_eq!(
            job.next_attempt_at.as_deref(),
            Some("1970-01-01T00:02:10.000Z")
        );
    }

    #[test]
    fn fenced_failure_finalize_uses_a_forward_clock_when_it_exceeds_the_cutoff() {
        let (_root, storage) = storage();
        confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        let token = reserve_token(&storage, &claim);
        assert_eq!(
            storage
                .finalize_fenced_vector_failure(
                    &token,
                    "RATE_LIMITED",
                    FencedFailureDecision::RetryAfter {
                        delay_millis: 30_000,
                    },
                    Some("definitely_not_sent"),
                    150_000,
                    100_000,
                )
                .unwrap(),
            FencedFailureFinalizeResult::RetryScheduled {
                next_attempt_at_millis: 180_000,
            }
        );
    }

    #[test]
    fn fenced_failure_finalize_blocks_on_attempt_limit_and_time_overflow() {
        let (_first_root, first_storage) = storage();
        let final_slot_claim = claim_before_final_attempt_slot(&first_storage);
        let final_slot_token = reserve_token(&first_storage, &final_slot_claim);
        assert_eq!(final_slot_token.attempt_ordinal(), MAX_VECTOR_SYNC_ATTEMPTS);
        assert_eq!(
            first_storage
                .finalize_fenced_vector_failure(
                    &final_slot_token,
                    "RATE_LIMITED",
                    FencedFailureDecision::Blocked,
                    Some("definitely_not_sent"),
                    100_000,
                    100_000,
                )
                .unwrap(),
            FencedFailureFinalizeResult::Blocked
        );
        let job = first_storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::Blocked);
        assert_eq!(job.next_attempt_at, None);
        assert_eq!(job.attempt_count as i64, MAX_VECTOR_SYNC_ATTEMPTS);
        assert_eq!(job.last_error_code.as_deref(), Some("RATE_LIMITED"));

        let (_root, storage) = storage();
        let overflow_claim = claimed_upsert(&storage);
        let overflow_token = reserve_token(&storage, &overflow_claim);
        assert_eq!(overflow_token.attempt_ordinal(), 1);
        assert_eq!(
            storage
                .finalize_fenced_vector_failure(
                    &overflow_token,
                    "RATE_LIMITED",
                    FencedFailureDecision::RetryAfter {
                        delay_millis: 30_000,
                    },
                    Some("definitely_not_sent"),
                    i64::MAX,
                    100_000,
                )
                .unwrap(),
            FencedFailureFinalizeResult::Blocked
        );
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::Blocked);
        assert_eq!(job.next_attempt_at, None);
        assert_eq!(job.attempt_count, 1);
        assert_eq!(job.last_error_code.as_deref(), Some("RATE_LIMITED"));
    }

    #[test]
    fn fenced_claim_with_cutoff_keeps_pending_eligible_and_excludes_later_retry_wait() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET state='retry_wait', next_attempt_at='1970-01-01T00:02:10.000Z'",
                [],
            )
            .unwrap();
        assert!(storage
            .claim_one_fenced_vector_sync_with_retry_cutoff(
                "generation-a",
                "descriptor-a",
                2,
                "worker-a",
                Some(100_000),
            )
            .unwrap()
            .is_none());
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id,
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        assert!(storage
            .claim_one_fenced_vector_sync_with_retry_cutoff(
                "generation-a",
                "descriptor-a",
                2,
                "worker-a",
                Some(100_000),
            )
            .unwrap()
            .is_some());
    }

    /// The reservation is atomic *and* idempotent per claim epoch. Repeating it on
    /// the same claim is a re-read of the slot that claim already owns, not a new
    /// Attempt: this replaces the pre-ATT-I2 behaviour where a second mark on one
    /// claim consumed a second budget slot.
    #[test]
    fn mark_fenced_attempt_started_returns_the_atomic_persisted_count() {
        let (_root, storage) = storage();
        confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();

        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 },
            "a repeated mark on one claim is idempotent, not a second Attempt"
        );
        assert_eq!(storage.list("life").unwrap()[0].attempt_count, 1);
        let epochs = attempt_epochs(&storage, claim.memory_id());
        assert_eq!(
            epochs,
            (claim.fenced_claim_epoch(), claim.fenced_claim_epoch())
        );
    }

    /// Matrix items 1-3: every successful ordinary claim takes a new
    /// `fenced_claim_epoch`, including when the owner and runtime fence are reused,
    /// and a claim never touches `last_marked_claim_epoch`.
    #[test]
    fn ordinary_claim_advances_fenced_claim_epoch_without_marking() {
        let (_root, storage) = storage();
        let first = claimed_upsert(&storage);
        assert_eq!(first.fenced_claim_epoch(), 1);
        assert_eq!(attempt_epochs(&storage, first.memory_id()), (1, 0));

        // Let the real expired-processing recovery release an unmarked claim,
        // then re-claim with the same owner so the runtime fence is renewed.
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET lease_expires_at='2000-01-01T00:00:00.000Z' WHERE id=?1",
                params![first.id()],
            )
            .unwrap();
        let second = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();

        assert_eq!(
            second.fence_epoch(),
            first.fence_epoch(),
            "the runtime fence is reused by the same owner"
        );
        assert_eq!(
            second.fenced_claim_epoch(),
            2,
            "a new claim cycle must still take a new claim epoch"
        );
        assert_eq!(
            attempt_epochs(&storage, second.memory_id()),
            (2, 0),
            "claiming must never advance last_marked_claim_epoch"
        );
        // The superseded claim epoch can no longer reserve anything.
        assert!(storage.reserve_fenced_attempt(&first).unwrap().is_lost());
        assert_eq!(attempt_epochs(&storage, second.memory_id()), (2, 0));
    }

    /// Matrix item 4: a row whose claim epoch cannot advance without overflowing
    /// fails closed instead of wrapping, saturating, or going negative.
    #[test]
    fn ordinary_claim_fails_closed_when_the_claim_epoch_cannot_advance() {
        let (_root, storage) = storage();
        let claim = claimed_upsert(&storage);
        // Let the real expired-processing recovery return an unmarked claim to
        // ordinary work, then push its claim epoch to the ceiling.
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET lease_expires_at='2000-01-01T00:00:00.000Z',
                     fenced_claim_epoch=9223372036854775807
                 WHERE id=?1",
                params![claim.id()],
            )
            .unwrap();

        assert!(storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a",)
            .unwrap()
            .is_none());

        let snapshot = storage
            .test_get_outbox_snapshot_detailed("life", claim.memory_id())
            .unwrap();
        assert_eq!(snapshot.state, "blocked");
        assert_eq!(
            snapshot.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );
        assert_eq!(snapshot.lease_owner, None);
        assert_eq!(snapshot.lease_fence_epoch, None);
        assert_eq!(snapshot.next_attempt_at, None);
        assert_eq!(
            attempt_epochs(&storage, claim.memory_id()),
            (i64::MAX, 0),
            "a fail-closed epoch is preserved exactly, never wrapped"
        );
    }

    /// Matrix items 5, 6, 8, 20: counts below the budget can claim and reserve; an
    /// at-limit row converges to `blocked` exactly once and is never claimable, so a
    /// sixth slot cannot exist.
    #[test]
    fn attempt_limit_allows_the_first_five_slots_and_blocks_the_sixth() {
        let (_root, storage) = storage();
        let mut claim = claimed_upsert(&storage);
        let memory_id = claim.memory_id().to_owned();

        for expected_ordinal in 1..=MAX_VECTOR_SYNC_ATTEMPTS {
            let reservation = storage.reserve_fenced_attempt(&claim).unwrap();
            assert_eq!(
                reservation.ordinal(),
                Some(expected_ordinal),
                "slot {expected_ordinal} must be granted"
            );
            assert_eq!(
                attempt_epochs(&storage, &memory_id),
                (expected_ordinal, expected_ordinal),
                "each reservation marks its own claim epoch"
            );
            if expected_ordinal == MAX_VECTOR_SYNC_ATTEMPTS {
                break;
            }
            // Release and re-claim to obtain a fresh claim epoch for the next slot.
            assert_eq!(
                storage
                    .test_fail_claim_via_real_reserved_token(
                        &claim,
                        "PROVIDER_UNAVAILABLE",
                        FencedFailureDecision::RetryAfter { delay_millis: 1 },
                        Some("definitely_not_sent"),
                        0,
                        0,
                    )
                    .unwrap(),
                FencedFailureFinalizeResult::RetryScheduled {
                    next_attempt_at_millis: 1,
                }
            );
            claim = storage
                .claim_one_fenced_vector_sync_with_retry_cutoff(
                    "generation-a",
                    "descriptor-a",
                    2,
                    "worker-a",
                    Some(60_000),
                )
                .unwrap()
                .expect("a count below the budget stays claimable");
        }

        // The fifth slot is reserved. Release the row so it becomes ordinary work.
        assert_eq!(
            storage
                .test_fail_claim_via_real_reserved_token(
                    &claim,
                    "PROVIDER_UNAVAILABLE",
                    FencedFailureDecision::RetryAfter { delay_millis: 1 },
                    Some("definitely_not_sent"),
                    0,
                    0,
                )
                .unwrap(),
            FencedFailureFinalizeResult::RetryScheduled {
                next_attempt_at_millis: 1,
            }
        );

        // The at-limit row must not be claimable, and must converge once.
        assert!(storage
            .claim_one_fenced_vector_sync_with_retry_cutoff(
                "generation-a",
                "descriptor-a",
                2,
                "worker-a",
                Some(60_000),
            )
            .unwrap()
            .is_none());
        let converged = storage
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(converged.state, "blocked");
        assert_eq!(converged.attempt_count, MAX_VECTOR_SYNC_ATTEMPTS);
        assert_eq!(converged.last_error_code.as_deref(), Some("MAX_ATTEMPTS"));
        assert_eq!(converged.next_attempt_at, None);
        assert_eq!(converged.lease_owner, None);
        assert_eq!(converged.lease_fence_epoch, None);
        assert_eq!(converged.lease_expires_at, None);
        assert_eq!(
            converged.claimed_generation_id.as_deref(),
            Some("generation-a"),
            "the durable generation survives budget convergence"
        );
        let epochs_after_convergence = attempt_epochs(&storage, &memory_id);
        assert_eq!(
            epochs_after_convergence,
            (MAX_VECTOR_SYNC_ATTEMPTS, MAX_VECTOR_SYNC_ATTEMPTS),
            "convergence preserves both claim epochs"
        );

        // A second drain must not re-process the already converged row.
        assert!(storage
            .claim_one_fenced_vector_sync_with_retry_cutoff(
                "generation-a",
                "descriptor-a",
                2,
                "worker-a",
                Some(60_000),
            )
            .unwrap()
            .is_none());
        let stable = storage
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(stable.state, "blocked");
        assert_eq!(stable.attempt_count, MAX_VECTOR_SYNC_ATTEMPTS);
        assert_eq!(
            attempt_epochs(&storage, &memory_id),
            epochs_after_convergence
        );
    }

    /// Matrix items 7 and 12/19: a count beyond the budget is identity corruption,
    /// while an at-limit *already marked* claim stays an idempotent re-read that
    /// returns ordinal 5 rather than a spurious sixth Attempt.
    #[test]
    fn attempt_limit_treats_over_budget_as_invariant_and_keeps_the_fifth_slot_idempotent() {
        // Over budget: INTERNAL_INVARIANT, no Provider or VectorStore permission.
        let (_over_root, over_budget) = storage();
        let claim = claimed_upsert(&over_budget);
        over_budget
            .test_set_fenced_attempt_count(MAX_VECTOR_SYNC_ATTEMPTS + 1)
            .unwrap();
        assert!(over_budget
            .reserve_fenced_attempt(&claim)
            .unwrap()
            .is_lost());
        let snapshot = over_budget
            .test_get_outbox_snapshot_detailed("life", claim.memory_id())
            .unwrap();
        assert_eq!(snapshot.state, "blocked");
        assert_eq!(
            snapshot.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );
        assert_eq!(
            snapshot.attempt_count,
            MAX_VECTOR_SYNC_ATTEMPTS + 1,
            "quarantine must not reduce the count"
        );
        assert_eq!(
            snapshot.claimed_generation_id.as_deref(),
            Some("generation-a"),
            "quarantine must not reset the generation"
        );
        assert_eq!(
            attempt_epochs(&over_budget, claim.memory_id()),
            (1, 1),
            "quarantine must not reset either claim epoch"
        );
        // Manual retry must not reopen an identity-corrupt row.
        over_budget.retry_failures("life").unwrap();
        assert_eq!(
            over_budget
                .test_get_outbox_snapshot_detailed("life", claim.memory_id())
                .unwrap()
                .state,
            "blocked"
        );

        // At limit but already marked by this very claim: idempotent ordinal 5.
        let (_at_limit_root, at_limit_storage) = storage();
        let claim = claimed_upsert(&at_limit_storage);
        at_limit_storage
            .test_set_fenced_attempt_count(MAX_VECTOR_SYNC_ATTEMPTS)
            .unwrap();
        let reservation = at_limit_storage.reserve_fenced_attempt(&claim).unwrap();
        assert_eq!(
            reservation.ordinal(),
            Some(MAX_VECTOR_SYNC_ATTEMPTS),
            "the fifth reserved slot re-reads as ordinal 5, not a sixth Attempt"
        );
        assert_eq!(
            at_limit_storage
                .test_get_outbox_snapshot_detailed("life", claim.memory_id())
                .unwrap()
                .state,
            "processing",
            "an idempotent re-read must not disturb a live claim"
        );
        assert_eq!(attempt_epochs(&at_limit_storage, claim.memory_id()), (1, 1));
    }

    /// Matrix item 20 from the reserve side: a *new* claim at the budget ceiling is
    /// refused a sixth slot and converges instead.
    #[test]
    fn attempt_limit_refuses_a_sixth_slot_to_a_new_claim() {
        let (_sixth_root, sixth_slot) = storage();
        let claim = claimed_upsert(&sixth_slot);
        // At the ceiling, with this claim's epoch deliberately unmarked: the row
        // spent its budget under earlier claims.
        sixth_slot
            .state()
            .unwrap()
            .connection
            .execute(
                &format!(
                    "UPDATE memory_vector_sync_outbox
                     SET attempt_count={MAX_VECTOR_SYNC_ATTEMPTS},
                         fenced_claim_epoch=9, last_marked_claim_epoch=8"
                ),
                [],
            )
            .unwrap();
        // The claim must describe the row's current epoch to be considered current.
        let claim = FencedVectorSyncClaim {
            fenced_claim_epoch: 9,
            ..claim
        };

        let reservation = sixth_slot.reserve_fenced_attempt(&claim).unwrap();
        assert!(
            reservation.is_budget_exhausted(),
            "a new claim cannot take a sixth slot"
        );
        assert_eq!(reservation.ordinal(), None);
        let snapshot = sixth_slot
            .test_get_outbox_snapshot_detailed("life", claim.memory_id())
            .unwrap();
        assert_eq!(snapshot.state, "blocked");
        assert_eq!(snapshot.attempt_count, MAX_VECTOR_SYNC_ATTEMPTS);
        assert_eq!(snapshot.last_error_code.as_deref(), Some("MAX_ATTEMPTS"));
        assert_eq!(
            attempt_epochs(&sixth_slot, claim.memory_id()),
            (9, 8),
            "refusing a slot must not advance either epoch"
        );

        // The pre-ATT-I3 wrapper surfaces this as a fail-closed outcome.
        let (_wrapper_root, wrapper_storage) = storage();
        let wrapper_claim = claimed_upsert(&wrapper_storage);
        wrapper_storage
            .state()
            .unwrap()
            .connection
            .execute(
                &format!(
                    "UPDATE memory_vector_sync_outbox
                     SET attempt_count={MAX_VECTOR_SYNC_ATTEMPTS},
                         fenced_claim_epoch=9, last_marked_claim_epoch=8"
                ),
                [],
            )
            .unwrap();
        let wrapper_claim = FencedVectorSyncClaim {
            fenced_claim_epoch: 9,
            ..wrapper_claim
        };
        assert_eq!(
            wrapper_storage
                .mark_fenced_attempt_started(&wrapper_claim)
                .unwrap(),
            FencedAttemptStartResult::LostLeaseOrSuperseded
        );
    }

    #[test]
    fn mark_fenced_attempt_started_rejects_mismatched_claim_fields_without_incrementing() {
        let cases = [
            (
                "mutation sequence",
                "UPDATE memory_vector_sync_outbox SET mutation_sequence=mutation_sequence+1",
            ),
            (
                "target revision",
                "UPDATE memory_vector_sync_outbox SET target_revision=target_revision+1",
            ),
            (
                "target hash",
                "UPDATE memory_vector_sync_outbox SET target_content_hash='different-hash'",
            ),
            (
                "claimed generation",
                "UPDATE memory_vector_sync_outbox SET claimed_generation_id='generation-b'",
            ),
            (
                "owner",
                "UPDATE memory_vector_sync_outbox SET lease_owner='worker-b'",
            ),
        ];

        for (name, mutation) in cases {
            let (_root, storage) = storage();
            confirmed(&storage, false);
            storage
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let claim = storage
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            storage
                .state()
                .unwrap()
                .connection
                .execute(mutation, [])
                .unwrap();

            assert_eq!(
                storage.mark_fenced_attempt_started(&claim).unwrap(),
                FencedAttemptStartResult::LostLeaseOrSuperseded,
                "{name} mismatch must fail closed"
            );
            assert_eq!(
                storage.list("life").unwrap()[0].attempt_count,
                0,
                "{name} mismatch must not consume an attempt"
            );
        }
    }

    #[test]
    fn mark_fenced_attempt_started_rejects_an_old_fence_from_an_independent_storage_service() {
        let (root, first) = storage();
        confirmed(&first, false);
        first
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let old_claim = first
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();

        first.test_expire_fenced_runtime_lease().unwrap();
        let new_claim = second
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-b")
            .unwrap()
            .unwrap();
        assert_ne!(old_claim.fence_epoch(), new_claim.fence_epoch());
        assert_eq!(
            first.mark_fenced_attempt_started(&old_claim).unwrap(),
            FencedAttemptStartResult::LostLeaseOrSuperseded
        );
        assert_eq!(first.list("life").unwrap()[0].attempt_count, 0);
    }

    #[test]
    fn mark_fenced_attempt_started_rejects_a_superseded_mutation_without_incrementing() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id,
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();

        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::LostLeaseOrSuperseded
        );
        assert_eq!(storage.list("life").unwrap()[0].attempt_count, 0);
    }

    /// Matrix items 9-12, 18, 22, 23: the first reservation writes the marked epoch
    /// and returns ordinal 1; repeating it on the same claim returns the identical
    /// ordinal and an equivalent token; a stale claim epoch cannot reserve; and the
    /// token guard accepts only the current reservation.
    #[test]
    fn reserve_fenced_attempt_is_idempotent_per_claim_epoch() {
        let (_root, storage) = storage();
        let claim = claimed_upsert(&storage);
        let memory_id = claim.memory_id().to_owned();
        assert_eq!(attempt_epochs(&storage, &memory_id), (1, 0));

        let first = storage.reserve_fenced_attempt(&claim).unwrap();
        let first_token = first.token().expect("the first reservation is granted");
        assert_eq!(first_token.attempt_ordinal(), 1);
        assert_eq!(first_token.fenced_claim_epoch(), 1);
        assert_eq!(
            attempt_epochs(&storage, &memory_id),
            (1, 1),
            "the first reservation marks its own claim epoch"
        );
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap()
                .last_send_disposition
                .as_deref(),
            Some("possibly_sent"),
            "an upsert reservation records that a send may have happened"
        );

        // The token guard accepts the reservation that is actually current.
        assert!(storage
            .validate_fenced_attempt_token_current(first_token)
            .unwrap());

        // Repeat the same reservation: same ordinal, equivalent token, no new slot.
        let repeat = storage.reserve_fenced_attempt(&claim).unwrap();
        let repeat_token = repeat.token().expect("a repeat reservation still succeeds");
        assert_eq!(repeat_token.attempt_ordinal(), 1);
        assert_eq!(repeat_token.fenced_claim_epoch(), 1);
        assert_eq!(repeat_token.outbox_id(), first_token.outbox_id());
        assert_eq!(
            repeat_token.mutation_sequence(),
            first_token.mutation_sequence()
        );
        assert_eq!(repeat_token.action(), first_token.action());
        assert_eq!(repeat_token.generation_id(), first_token.generation_id());
        assert_eq!(repeat_token.lease_owner(), first_token.lease_owner());
        assert_eq!(repeat_token.fence_epoch(), first_token.fence_epoch());
        assert_eq!(
            repeat_token.target_revision(),
            first_token.target_revision()
        );
        assert_eq!(
            repeat_token.target_content_hash(),
            first_token.target_content_hash()
        );
        assert_eq!(
            attempt_epochs(&storage, &memory_id),
            (1, 1),
            "a repeated reservation advances nothing"
        );
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap()
                .attempt_count,
            1
        );

        // A claim describing a superseded claim epoch cannot reserve, and its token
        // is no longer current.
        let stale_epoch_claim = FencedVectorSyncClaim {
            fenced_claim_epoch: claim.fenced_claim_epoch() - 1,
            ..claim
        };
        assert!(storage
            .reserve_fenced_attempt(&stale_epoch_claim)
            .unwrap()
            .is_lost());
        assert!(storage
            .validate_fenced_attempt_token_current(first_token)
            .unwrap());
        assert_eq!(attempt_epochs(&storage, &memory_id), (1, 1));
    }

    #[test]
    fn fenced_attempt_token_ordinal_cas_rejects_stale_success_and_failure() {
        let (_success_root, success_storage) = storage();
        let success_claim = claimed_upsert(&success_storage);
        let success_token = reserve_token(&success_storage, &success_claim);
        success_storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET attempt_count=attempt_count+1 WHERE id=?1",
                params![success_claim.id()],
            )
            .unwrap();
        let before_success_finalize = success_storage
            .test_get_outbox_snapshot_detailed(success_claim.life_id(), success_claim.memory_id())
            .unwrap();
        assert_eq!(before_success_finalize.attempt_count, 2);
        assert_eq!(
            success_storage
                .finalize_fenced_vector_sync(&success_token)
                .unwrap(),
            FencedFinalizeResult::LostLeaseOrSuperseded
        );
        assert_eq!(
            success_storage
                .test_get_outbox_snapshot_detailed(
                    success_claim.life_id(),
                    success_claim.memory_id(),
                )
                .unwrap(),
            before_success_finalize,
            "a token with ordinal 1 cannot success-finalize an ordinal-2 row"
        );

        let (_root, storage) = storage();
        let failure_claim = claimed_upsert(&storage);
        let failure_token = reserve_token(&storage, &failure_claim);
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox SET attempt_count=attempt_count+1 WHERE id=?1",
                params![failure_claim.id()],
            )
            .unwrap();
        let before_failure_finalize = storage
            .test_get_outbox_snapshot_detailed(failure_claim.life_id(), failure_claim.memory_id())
            .unwrap();
        assert_eq!(before_failure_finalize.attempt_count, 2);
        assert_eq!(
            storage
                .finalize_fenced_vector_failure(
                    &failure_token,
                    "PROVIDER_UNAVAILABLE",
                    FencedFailureDecision::RetryAfter { delay_millis: 1 },
                    Some("definitely_not_sent"),
                    0,
                    0,
                )
                .unwrap(),
            FencedFailureFinalizeResult::LostLeaseOrSuperseded
        );
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed(
                    failure_claim.life_id(),
                    failure_claim.memory_id(),
                )
                .unwrap(),
            before_failure_finalize,
            "a token with ordinal 1 cannot failure-finalize an ordinal-2 row"
        );
    }

    /// Matrix item 21: a reservation that committed but whose result never reached
    /// the caller is safe to retry — the retry consumes no second slot and returns
    /// the same ordinal and token identity.
    #[test]
    fn validate_fenced_attempt_token_current_is_read_only_on_invalid_or_generation_mismatch() {
        assert_fenced_attempt_token_guard_is_read_only("generation mismatch", |storage, claim| {
            storage
                .state()
                .unwrap()
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET claimed_generation_id='generation-b' WHERE id=?1",
                    params![claim.id()],
                )
                .unwrap();
        });
        assert_fenced_attempt_token_guard_is_read_only(
            "missing durable generation",
            |storage, claim| {
                storage
                    .state()
                    .unwrap()
                    .connection
                    .execute(
                        "UPDATE memory_vector_sync_outbox
                     SET claimed_generation_id=NULL WHERE id=?1",
                        params![claim.id()],
                    )
                    .unwrap();
            },
        );
        assert_fenced_attempt_token_guard_is_read_only(
            "invalid epoch relationship",
            |storage, claim| {
                let state = storage.state().unwrap();
                state
                    .connection
                    .execute_batch("PRAGMA ignore_check_constraints=ON")
                    .unwrap();
                state
                    .connection
                    .execute(
                        "UPDATE memory_vector_sync_outbox
                     SET last_marked_claim_epoch=fenced_claim_epoch+1 WHERE id=?1",
                        params![claim.id()],
                    )
                    .unwrap();
                state
                    .connection
                    .execute_batch("PRAGMA ignore_check_constraints=OFF")
                    .unwrap();
            },
        );
        assert_fenced_attempt_token_guard_is_read_only(
            "invalid Attempt count",
            |storage, claim| {
                storage
                    .state()
                    .unwrap()
                    .connection
                    .execute(
                        &format!(
                            "UPDATE memory_vector_sync_outbox
                         SET attempt_count={} WHERE id=?1",
                            MAX_VECTOR_SYNC_ATTEMPTS + 1
                        ),
                        params![claim.id()],
                    )
                    .unwrap();
            },
        );
        assert_fenced_attempt_token_guard_is_read_only("target mismatch", |storage, claim| {
            storage
                .state()
                .unwrap()
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET target_revision=target_revision+1 WHERE id=?1",
                    params![claim.id()],
                )
                .unwrap();
        });
        assert_fenced_attempt_token_guard_is_read_only(
            "stale row lease fence",
            |storage, claim| {
                storage
                    .state()
                    .unwrap()
                    .connection
                    .execute(
                        "UPDATE memory_vector_sync_outbox
                     SET lease_fence_epoch=lease_fence_epoch+1 WHERE id=?1",
                        params![claim.id()],
                    )
                    .unwrap();
            },
        );
    }

    #[test]
    fn stale_same_owner_claim_epoch_cannot_success_finalize_fenced_vector_sync() {
        let (_root, storage) = storage();
        let (old_claim, current_claim) = same_owner_same_fence_epoch_pair(&storage);
        let before = storage
            .test_get_outbox_snapshot_detailed(current_claim.life_id(), current_claim.memory_id())
            .unwrap();
        assert_eq!(before.state, "processing");
        assert_eq!(before.attempt_count, 1);
        assert_eq!(
            before.fenced_claim_epoch,
            current_claim.fenced_claim_epoch()
        );
        assert_eq!(
            before.last_marked_claim_epoch,
            old_claim.fenced_claim_epoch()
        );
        assert_eq!(
            before.last_send_disposition.as_deref(),
            Some("definitely_not_sent")
        );
        assert_eq!(
            before.last_error_code.as_deref(),
            Some("PROVIDER_UNAVAILABLE")
        );

        assert!(!storage.fenced_vector_claim_is_current(&old_claim).unwrap());
        assert_eq!(
            storage
                .test_complete_claim_via_real_reserved_token(
                    &old_claim,
                    Some("old-epoch-content-hash"),
                    None,
                    false,
                    None,
                )
                .unwrap(),
            FencedFinalizeResult::LostLeaseOrSuperseded
        );
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed(
                    current_claim.life_id(),
                    current_claim.memory_id()
                )
                .unwrap(),
            before,
            "an old epoch may not change the new claim's row or lease"
        );
        assert!(storage
            .fenced_vector_claim_is_current(&current_claim)
            .unwrap());
        assert_eq!(
            storage
                .test_complete_claim_via_real_reserved_token(
                    &current_claim,
                    Some("current-epoch-content-hash"),
                    None,
                    false,
                    None,
                )
                .unwrap(),
            FencedFinalizeResult::Applied
        );
    }

    #[test]
    fn stale_same_owner_claim_epoch_cannot_failure_finalize_fenced_vector_failure() {
        let (_root, storage) = storage();
        let (old_claim, current_claim) = same_owner_same_fence_epoch_pair(&storage);
        let before = storage
            .test_get_outbox_snapshot_detailed(current_claim.life_id(), current_claim.memory_id())
            .unwrap();

        assert!(!storage.fenced_vector_claim_is_current(&old_claim).unwrap());
        assert_eq!(
            storage
                .test_fail_claim_via_real_reserved_token(
                    &old_claim,
                    "PROVIDER_UNAVAILABLE",
                    FencedFailureDecision::Blocked,
                    Some("definitely_not_sent"),
                    0,
                    0,
                )
                .unwrap(),
            FencedFailureFinalizeResult::LostLeaseOrSuperseded
        );
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed(
                    current_claim.life_id(),
                    current_claim.memory_id()
                )
                .unwrap(),
            before,
            "an old epoch may not change the new claim's state, evidence, or lease"
        );
        assert!(storage
            .fenced_vector_claim_is_current(&current_claim)
            .unwrap());
        assert_eq!(
            storage
                .test_fail_claim_via_real_reserved_token(
                    &current_claim,
                    "PROVIDER_UNAVAILABLE",
                    FencedFailureDecision::RetryAfter { delay_millis: 1 },
                    Some("definitely_not_sent"),
                    0,
                    0,
                )
                .unwrap(),
            FencedFailureFinalizeResult::RetryScheduled {
                next_attempt_at_millis: 1
            }
        );
    }

    #[test]
    fn reserve_fenced_attempt_survives_an_unknown_commit_result() {
        let (_root, storage) = storage();
        let claim = claimed_upsert(&storage);
        let memory_id = claim.memory_id().to_owned();

        // The seam fires strictly after the reservation transaction commits, so the
        // database really is updated while the caller only observes an error.
        fail_next_reserve_after_commit_for_test();
        let lost = storage.reserve_fenced_attempt(&claim);
        assert!(
            lost.is_err(),
            "the caller must not learn the reservation outcome"
        );
        // Proof the commit really happened despite the caller's error.
        assert_eq!(
            attempt_epochs(&storage, &memory_id),
            (1, 1),
            "the reservation is durable even though its result was lost"
        );
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap()
                .attempt_count,
            1
        );

        // The caller retries with the same claim and recovers the same slot.
        let retried = storage.reserve_fenced_attempt(&claim).unwrap();
        assert_eq!(
            retried.ordinal(),
            Some(1),
            "the retry recovers the same Attempt rather than consuming another"
        );
        assert_eq!(attempt_epochs(&storage, &memory_id), (1, 1));
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap()
                .attempt_count,
            1,
            "an unknown commit result must cost exactly one Attempt"
        );
    }

    /// Matrix item 40: idempotency is a property of persisted state, so it survives
    /// dropping the connection and reopening the database.
    #[test]
    fn reserve_fenced_attempt_stays_idempotent_after_reopen() {
        let (root, first) = storage();
        let claim = claimed_upsert(&first);
        let memory_id = claim.memory_id().to_owned();
        assert_eq!(
            first.reserve_fenced_attempt(&claim).unwrap().ordinal(),
            Some(1)
        );
        drop(first);

        let reopened = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        assert_eq!(
            reopened.reserve_fenced_attempt(&claim).unwrap().ordinal(),
            Some(1),
            "a reopened database still recognizes the reserved slot"
        );
        assert_eq!(attempt_epochs(&reopened, &memory_id), (1, 1));
        assert_eq!(
            reopened
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap()
                .attempt_count,
            1
        );
    }

    /// Matrix items 35, 36: a migration-isolated row can neither be claimed nor
    /// reserved, and a raw unauthorized connection cannot tamper with the Attempt
    /// columns because the writer fence rejects its writes.
    #[test]
    fn migration_isolated_and_raw_connections_cannot_touch_attempt_state() {
        let (_fence_root, fenced) = storage();
        let claim = claimed_upsert(&fenced);
        let memory_id = claim.memory_id().to_owned();
        assert_eq!(
            fenced.reserve_fenced_attempt(&claim).unwrap().ordinal(),
            Some(1)
        );

        // A raw connection has no writer-epoch capability, so the 18 writer fences
        // reject any attempt to rewrite the count or either epoch.
        let database_path = fenced.test_database_main_path().unwrap();
        let raw = Connection::open(&database_path).unwrap();
        for statement in [
            "UPDATE memory_vector_sync_outbox SET attempt_count=0",
            "UPDATE memory_vector_sync_outbox SET fenced_claim_epoch=99",
            "UPDATE memory_vector_sync_outbox SET last_marked_claim_epoch=0",
        ] {
            assert!(
                raw.execute(statement, []).is_err(),
                "the writer fence must reject: {statement}"
            );
        }
        drop(raw);
        assert_eq!(attempt_epochs(&fenced, &memory_id), (1, 1));
        assert_eq!(
            fenced
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap()
                .attempt_count,
            1
        );

        // A migration-isolated row is outside ordinary work entirely.
        let (_isolated_root, isolated) = storage();
        isolated
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        isolated
            .test_insert_legacy_quarantine_fixture("life", "isolated-memory")
            .unwrap();
        assert!(isolated
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .is_none());
        let snapshot = isolated
            .test_get_outbox_snapshot_detailed("life", "isolated-memory")
            .unwrap();
        assert_eq!(
            snapshot.migration_disposition.as_deref(),
            Some("legacy_upsert_rebuild_required")
        );
        assert_eq!(snapshot.attempt_count, 0);
        assert_eq!(attempt_epochs(&isolated, "isolated-memory"), (0, 0));
    }

    #[test]
    fn fenced_attempt_and_finalize_require_the_current_runtime_lease() {
        let (_root, storage) = storage();
        confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(storage.list("life").unwrap()[0].attempt_count, 0);
        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        assert_eq!(storage.list("life").unwrap()[0].attempt_count, 1);

        let state = storage.state().unwrap();
        state
            .connection
            .execute(
                "UPDATE memory_vector_sync_runtime_lease SET expires_at='2000-01-01T00:00:00.000Z'",
                [],
            )
            .unwrap();
        drop(state);
        assert!(!storage.fenced_vector_claim_is_current(&claim).unwrap());
        assert!(!storage.mark_fenced_attempt_started(&claim).unwrap());
        assert_eq!(
            storage
                .test_complete_claim_via_real_reserved_token(
                    &claim,
                    None,
                    Some("VECTOR_TARGET_STALE"),
                    false,
                    None,
                )
                .unwrap(),
            FencedFinalizeResult::LostLeaseOrSuperseded
        );
        let job = storage.list("life").unwrap().remove(0);
        assert_eq!(job.state, MemoryVectorSyncState::Processing);
        assert_eq!(job.attempt_count, 1);
    }

    #[test]
    fn fenced_claim_current_requires_both_unexpired_leases() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let runtime_before: String = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT expires_at FROM memory_vector_sync_runtime_lease
                 WHERE lease_name='memory-vector-single-event-consumer'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(storage.fenced_vector_claim_is_current(&claim).unwrap());
        let runtime_after: String = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT expires_at FROM memory_vector_sync_runtime_lease
                 WHERE lease_name='memory-vector-single-event-consumer'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            runtime_after, runtime_before,
            "current guard must not renew"
        );

        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET lease_expires_at='2000-01-01T00:00:00.000Z'
                 WHERE life_id=?1 AND memory_id=?2",
                params![record.life_id, record.id],
            )
            .unwrap();
        assert!(!storage.fenced_vector_claim_is_current(&claim).unwrap());
        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::LostLeaseOrSuperseded
        );
        let expired = storage
            .test_get_outbox_snapshot_detailed("life", claim.memory_id())
            .unwrap();
        assert_eq!(expired.state, "processing");
        assert_eq!(expired.attempt_count, 0);
        assert_eq!(
            expired.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
        assert_eq!(expired.lease_owner.as_deref(), Some("worker-a"));
        assert_eq!(expired.lease_fence_epoch, Some(claim.fence_epoch()));
        assert_eq!(
            expired.lease_expires_at.as_deref(),
            Some("2000-01-01T00:00:00.000Z")
        );
        assert_eq!(expired.last_error_code, None);
        assert_eq!(expired.last_send_disposition, None);
    }

    #[test]
    fn fenced_claim_current_stale_mutation_does_not_quarantine_replacement() {
        let (root, first) = storage();
        let record = confirmed(&first, false);
        first
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = first
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let old = first
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        let old_revision = old.target_revision.expect("old revision");
        let old_hash = old.target_content_hash.clone().expect("old hash");
        first
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET claimed_generation_id=NULL
                 WHERE life_id=?1 AND memory_id=?2",
                params![record.life_id, record.id],
            )
            .unwrap();

        let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        let update = MemoryRevisionService::new(&second)
            .update_confirmed(UpdateConfirmedMemoryRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                expected_revision: old_revision,
                kind: MemoryKind::Fact,
                content: "stale worker replacement content".into(),
                summary: Some("stale worker replacement summary".into()),
            })
            .unwrap();
        assert!(update.revision > old_revision);

        assert!(!first.fenced_vector_claim_is_current(&claim).unwrap());
        let replacement = first
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        assert_eq!(replacement.state, "pending");
        assert!(replacement.mutation_sequence > old.mutation_sequence);
        assert!(replacement.target_revision.expect("new revision") > old_revision);
        assert_ne!(
            replacement.target_content_hash.as_deref(),
            Some(old_hash.as_str())
        );
        assert_eq!(replacement.attempt_count, 0);
        assert_eq!(replacement.claimed_generation_id, None);
        assert_eq!(replacement.last_send_disposition, None);
        assert_eq!(replacement.last_error_code, None);
        assert_eq!(replacement.lease_owner, None);
        assert_eq!(replacement.lease_fence_epoch, None);
        assert_eq!(replacement.lease_expires_at, None);
    }

    #[test]
    fn embedding_send_disposition_is_persisted_only_for_embedding_failures() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        assert_eq!(
            storage
                .test_complete_claim_via_real_reserved_token(
                    &claim,
                    None,
                    Some("NETWORK_UNAVAILABLE"),
                    true,
                    Some("definitely_not_sent"),
                )
                .unwrap(),
            FencedFinalizeResult::Applied
        );
        let state = storage.state().unwrap();
        let saved: Option<String> = state
            .connection
            .query_row(
                "SELECT last_send_disposition FROM memory_vector_sync_outbox WHERE memory_id=?1",
                params![record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved.as_deref(), Some("definitely_not_sent"));
        drop(state);

        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let reset: Option<String> = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT last_send_disposition FROM memory_vector_sync_outbox WHERE memory_id=?1",
                params![record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(reset, None);
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        assert_eq!(
            storage
                .test_complete_claim_via_real_reserved_token(
                    &claim,
                    None,
                    Some("NETWORK_UNAVAILABLE"),
                    true,
                    Some("possibly_sent"),
                )
                .unwrap(),
            FencedFinalizeResult::Applied
        );
        let saved: Option<String> = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT last_send_disposition FROM memory_vector_sync_outbox WHERE memory_id=?1",
                params![record.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(saved.as_deref(), Some("possibly_sent"));
    }

    #[test]
    fn send_disposition_is_atomic_with_attempt_start() {
        {
            let (_root, storage) = storage();
            let record = confirmed(&storage, false);
            storage
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let claim = storage
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            assert_eq!(
                storage.mark_fenced_attempt_started(&claim).unwrap(),
                FencedAttemptStartResult::Started { attempt_count: 1 }
            );
            let started = storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(started.state, "processing");
            assert_eq!(started.attempt_count, 1);
            assert_eq!(
                started.last_send_disposition.as_deref(),
                Some("possibly_sent")
            );

            assert_eq!(
                storage
                    .test_fail_claim_via_real_reserved_token(
                        &claim,
                        "PROVIDER_UNAVAILABLE",
                        FencedFailureDecision::RetryAfter {
                            delay_millis: 30_000,
                        },
                        Some("definitely_not_sent"),
                        100_000,
                        100_000,
                    )
                    .unwrap(),
                FencedFailureFinalizeResult::RetryScheduled {
                    next_attempt_at_millis: 130_000,
                }
            );
            let next_claim = storage
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            let cleared = storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(cleared.state, "processing");
            assert_eq!(
                cleared.last_send_disposition.as_deref(),
                Some("definitely_not_sent")
            );
            assert_eq!(
                cleared.claimed_generation_id.as_deref(),
                Some("generation-a")
            );

            storage.test_expire_fenced_runtime_lease().unwrap();
            assert_eq!(
                storage.mark_fenced_attempt_started(&next_claim).unwrap(),
                FencedAttemptStartResult::LostLeaseOrSuperseded
            );
            let after_old_fence = storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(after_old_fence.attempt_count, 1);
            assert_eq!(
                after_old_fence.last_send_disposition.as_deref(),
                Some("definitely_not_sent")
            );
        }

        let (_root, delete_storage) = storage();
        let record = confirmed(&delete_storage, false);
        delete_storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        delete_storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let delete = delete_storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(
            delete_storage.mark_fenced_attempt_started(&delete).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        assert_eq!(
            delete_storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap()
                .last_send_disposition,
            None
        );
    }

    /// Recovery of an expired claim that already reserved its Attempt slot.
    ///
    /// Each `attempts > 0` fixture is written as a *marked* claim
    /// (`last_marked_claim_epoch == fenced_claim_epoch`), because that is what
    /// having consumed a slot means under ATT-I2: an unmarked row with
    /// `attempt_count > 0` describes a slot reserved by an *earlier* claim, which
    /// `recover_expired_unmarked_*` covers separately.
    #[test]
    fn delete_unknown_is_rejected_by_claim_reserve_recovery_and_retry() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let token = reserve_token(&storage, &claim);
        assert_eq!(
            storage.mark_fenced_delete_send_witness(&token).unwrap(),
            FencedDeleteWitnessResult::Marked
        );

        let witnessed = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(
            witnessed.last_send_disposition.as_deref(),
            Some("possibly_sent")
        );
        let witness_anchor = witnessed
            .delete_witness_at
            .as_deref()
            .expect("Delete witness must carry its durable time anchor");
        let resolution: (String, i64, String, i64, String) = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT r.witness_age_anchor_at,r.captured_generation_authority_epoch,
                        r.state,g.authority_epoch,o.delete_witness_at
                 FROM memory_vector_late_delete_resolution r
                 JOIN memory_vector_sync_outbox o ON o.id=r.outbox_id
                 JOIN memory_vector_generation g ON g.generation_id=r.claimed_generation_id
                 WHERE r.outbox_id=?1",
                [witnessed.id],
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
        assert_eq!(resolution.0, witness_anchor);
        assert_eq!(resolution.4, witness_anchor);
        assert_eq!(resolution.1, resolution.3);
        assert_eq!(resolution.2, "pending");

        // Reserve is independently fail-closed even though this direct test call
        // bypasses ordinary candidate selection.
        assert!(matches!(
            storage.reserve_fenced_attempt(&claim).unwrap(),
            FencedAttemptReservation::LostLeaseOrSuperseded
        ));
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap(),
            witnessed,
            "reserve must retain the Delete witness and all Attempt identity"
        );

        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET lease_expires_at='2000-01-01T00:00:00.000Z'
                     WHERE life_id=?1 AND memory_id=?2",
                    params![record.life_id, record.id],
                )
                .unwrap();
        }
        storage.test_expire_fenced_runtime_lease().unwrap();
        assert!(storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-b")
            .unwrap()
            .is_none());

        let recovered = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(recovered.state, "blocked");
        assert_eq!(recovered.attempt_count, witnessed.attempt_count);
        assert_eq!(
            recovered.claimed_generation_id, witnessed.claimed_generation_id,
            "recovery must retain the durable generation"
        );
        assert_eq!(recovered.fenced_claim_epoch, witnessed.fenced_claim_epoch);
        assert_eq!(
            recovered.last_marked_claim_epoch,
            witnessed.last_marked_claim_epoch
        );
        assert_eq!(
            recovered.last_send_disposition, witnessed.last_send_disposition,
            "recovery must not clear Unknown Delete evidence"
        );
        assert_eq!(
            recovered.delete_witness_at, witnessed.delete_witness_at,
            "recovery must not replace the original Delete witness time anchor"
        );
        assert_eq!(
            (
                recovered.lease_owner,
                recovered.lease_fence_epoch,
                recovered.lease_expires_at
            ),
            (None, None, None)
        );
        assert_eq!(storage.retry_failures("life").unwrap(), 0);
        assert_eq!(
            storage
                .inspect_outbox_sync_health("generation-a", MAX_VECTOR_SYNC_ATTEMPTS as u32, 0)
                .unwrap()
                .delete_replay_not_eligible_count,
            1
        );
    }

    #[test]
    fn delete_witness_commit_unknown_persists_runtime_resolution_anchor_and_captured_generation_authority(
    ) {
        let (root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let token = reserve_token(&storage, &claim);

        storage.test_fail_next_fenced_delete_witness_after_commit();
        assert!(storage.mark_fenced_delete_send_witness(&token).is_err());
        assert!(storage
            .fenced_delete_send_witness_is_persisted(&token)
            .unwrap());

        let reopened = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        let witnessed = reopened
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();
        let witness_anchor = witnessed.delete_witness_at.clone().unwrap();
        let row: (String, i64, String, i64, String) = reopened
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT r.witness_age_anchor_at,r.captured_generation_authority_epoch,
                        r.state,g.authority_epoch,o.delete_witness_at
                 FROM memory_vector_late_delete_resolution r
                 JOIN memory_vector_sync_outbox o ON o.id=r.outbox_id
                 JOIN memory_vector_generation g ON g.generation_id=r.claimed_generation_id
                 WHERE r.outbox_id=?1",
                [witnessed.id],
                |db_row| {
                    Ok((
                        db_row.get(0)?,
                        db_row.get(1)?,
                        db_row.get(2)?,
                        db_row.get(3)?,
                        db_row.get(4)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(row.0, witness_anchor);
        assert_eq!(row.4, witness_anchor);
        assert_eq!(row.1, row.3);
        assert_eq!(row.2, "pending");
    }

    #[test]
    fn delete_unknown_failure_finalize_without_a_pre_send_witness_rolls_back_fail_closed() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Delete,
            })
            .unwrap();
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let token = reserve_token(&storage, &claim);
        let before = storage
            .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
            .unwrap();

        assert!(storage
            .finalize_fenced_vector_failure(
                &token,
                "PROVIDER_RESULT_UNKNOWN",
                FencedFailureDecision::Blocked,
                None,
                0,
                0,
            )
            .is_err());
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap(),
            before,
            "no canonical Delete-Unknown row may commit without the pre-send witness"
        );
        let resolution_count: i64 = storage
            .state()
            .unwrap()
            .connection
            .query_row(
                "SELECT COUNT(*) FROM memory_vector_late_delete_resolution WHERE outbox_id=?1",
                [before.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(resolution_count, 0);
    }

    #[test]
    fn expired_upsert_with_possible_send_blocks() {
        let cases = [
            ("upsert", 0_i64, None, "pending", None, None),
            (
                "upsert",
                1_i64,
                Some("possibly_sent"),
                "blocked",
                Some("PROVIDER_RESULT_UNKNOWN"),
                Some("possibly_sent"),
            ),
            (
                "upsert",
                1_i64,
                None,
                "blocked",
                Some("INTERNAL_INVARIANT"),
                None,
            ),
            (
                "upsert",
                1_i64,
                Some("definitely_not_sent"),
                "blocked",
                Some("INTERNAL_INVARIANT"),
                Some("definitely_not_sent"),
            ),
            ("delete", 1_i64, None, "pending", None, None),
        ];

        for (action, attempts, disposition, expected_state, expected_error, expected_disposition) in
            cases
        {
            let (_root, storage) = storage();
            let record = confirmed(&storage, false);
            if action == "delete" {
                storage
                    .enqueue(EnqueueMemoryVectorSyncRequest {
                        life_id: record.life_id.clone(),
                        memory_id: record.id.clone(),
                        desired_action: MemoryVectorSyncAction::Delete,
                    })
                    .unwrap();
            }
            storage
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let claim = storage
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            let mut state = storage.state().unwrap();
            state
                .connection
                .execute(
                    // A reserved slot implies the claim marked its own epoch, so the
                    // fixture keeps the two claim epochs consistent with attempts.
                    "UPDATE memory_vector_sync_outbox
                     SET attempt_count=?1, last_send_disposition=?2,
                         last_marked_claim_epoch=CASE WHEN ?1 > 0 THEN fenced_claim_epoch ELSE 0 END,
                         lease_expires_at='2000-01-01T00:00:00.000Z'",
                    params![attempts, disposition],
                )
                .unwrap();
            let tx = state
                .connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            assert_eq!(
                recover_expired_fenced_processing_in(&tx, Some(1_700_000_000_000)).unwrap(),
                1
            );
            tx.commit().unwrap();
            drop(state);

            let snapshot = storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(snapshot.state, expected_state, "{action}/{attempts}");
            assert_eq!(snapshot.attempt_count, attempts, "{action}/{attempts}");
            assert_eq!(snapshot.last_error_code.as_deref(), expected_error);
            assert_eq!(
                snapshot.last_send_disposition.as_deref(),
                expected_disposition
            );
            assert_eq!(snapshot.lease_owner, None);
            assert_eq!(snapshot.lease_fence_epoch, None);
            assert_eq!(snapshot.lease_expires_at, None);
            assert_eq!(
                snapshot.claimed_generation_id.as_deref(),
                if attempts == 0 {
                    None
                } else {
                    Some("generation-a")
                }
            );
            assert_eq!(snapshot.next_attempt_at, None);
            drop(claim);
        }
    }

    #[test]
    fn expired_processing_leaves_a_live_fence_unchanged() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let _claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let before = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        let mut state = storage.state().unwrap();
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            recover_expired_fenced_processing_in(&tx, Some(0)).unwrap(),
            0
        );
        tx.commit().unwrap();
        drop(state);
        assert_eq!(
            storage
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap(),
            before
        );
    }

    #[test]
    fn generation_identity_is_immutable_after_registration() {
        let (_root, storage) = storage();
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let descriptor_error = storage
            .register_building_vector_generation("generation-a", "descriptor-b", 2)
            .unwrap_err();
        assert_eq!(descriptor_error.code, "GENERATION_DESCRIPTOR_MISMATCH");
        let dimension_error = storage
            .register_building_vector_generation("generation-a", "descriptor-a", 3)
            .unwrap_err();
        assert_eq!(dimension_error.code, "GENERATION_DIMENSION_MISMATCH");
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_generation SET state='active', authority_epoch=authority_epoch+1 WHERE generation_id='generation-a'",
                [],
            )
            .unwrap();
        let state_error = storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap_err();
        assert_eq!(state_error.code, "GENERATION_STATE_CONFLICT");
    }

    #[test]
    fn generation_binding_phase_requires_complete_ephemeral_claim_fields() {
        let facts = |state,
                     attempt_count,
                     claimed_generation_id,
                     lease_owner,
                     lease_fence_epoch,
                     lease_expires_at| {
            GenerationBindingFacts {
                state,
                attempt_count,
                claimed_generation_id,
                claimed_generation_authority_epoch: claimed_generation_id.map(|_| 1),
                lease_owner,
                lease_fence_epoch,
                lease_expires_at,
            }
        };
        assert_eq!(
            generation_binding_phase(facts("pending", 0, None, None, None, None)),
            GenerationBindingPhase::Unbound
        );
        assert_eq!(
            generation_binding_phase(facts(
                "processing",
                0,
                Some("generation-a"),
                Some("owner-a"),
                Some(1),
                Some("2099-01-01T00:00:00.000Z"),
            )),
            GenerationBindingPhase::Ephemeral
        );
        assert_eq!(
            generation_binding_phase(facts(
                "processing",
                0,
                Some("generation-a"),
                Some("owner-a"),
                Some(1),
                Some("2000-01-01T00:00:00.000Z"),
            )),
            GenerationBindingPhase::Ephemeral,
            "an expired but structurally valid pre-attempt claim remains Ephemeral"
        );
        assert_eq!(
            generation_binding_phase(facts(
                "retry_wait",
                1,
                Some("generation-a"),
                None,
                None,
                None
            )),
            GenerationBindingPhase::Durable
        );
        assert_eq!(
            generation_binding_phase(facts("pending", 1, None, None, None, None)),
            GenerationBindingPhase::MissingAfterAttempt
        );
        for (name, facts) in [
            (
                "non-processing",
                facts("pending", 0, Some("generation-a"), None, None, None),
            ),
            (
                "missing owner",
                facts(
                    "processing",
                    0,
                    Some("generation-a"),
                    None,
                    Some(1),
                    Some("2099-01-01T00:00:00.000Z"),
                ),
            ),
            (
                "empty owner",
                facts(
                    "processing",
                    0,
                    Some("generation-a"),
                    Some(""),
                    Some(1),
                    Some("2099-01-01T00:00:00.000Z"),
                ),
            ),
            (
                "missing fence",
                facts(
                    "processing",
                    0,
                    Some("generation-a"),
                    Some("owner-a"),
                    None,
                    Some("2099-01-01T00:00:00.000Z"),
                ),
            ),
            (
                "non-positive fence",
                facts(
                    "processing",
                    0,
                    Some("generation-a"),
                    Some("owner-a"),
                    Some(0),
                    Some("2099-01-01T00:00:00.000Z"),
                ),
            ),
            (
                "missing expiry",
                facts(
                    "processing",
                    0,
                    Some("generation-a"),
                    Some("owner-a"),
                    Some(1),
                    None,
                ),
            ),
            (
                "malformed expiry",
                facts(
                    "processing",
                    0,
                    Some("generation-a"),
                    Some("owner-a"),
                    Some(1),
                    Some("not-a-time"),
                ),
            ),
            (
                "processing without a binding",
                facts(
                    "processing",
                    0,
                    None,
                    Some("owner-a"),
                    Some(1),
                    Some("2099-01-01T00:00:00.000Z"),
                ),
            ),
        ] {
            assert_eq!(
                generation_binding_phase(facts),
                GenerationBindingPhase::Invalid,
                "{name}"
            );
        }
    }

    #[test]
    fn claim_one_fenced_vector_sync_preserves_generation_binding_across_retry_and_switch() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        storage
            .register_building_vector_generation("generation-b", "descriptor-a", 2)
            .unwrap();

        let first = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let ephemeral = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(ephemeral.attempt_count, 0);
        assert_eq!(ephemeral.state, "processing");
        assert_eq!(
            ephemeral.claimed_generation_id.as_deref(),
            Some("generation-a")
        );

        assert_eq!(
            storage.mark_fenced_attempt_started(&first).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        assert_eq!(
            storage
                .test_fail_claim_via_real_reserved_token(
                    &first,
                    "RATE_LIMITED",
                    FencedFailureDecision::RetryAfter {
                        delay_millis: 30_000,
                    },
                    Some("definitely_not_sent"),
                    0,
                    0,
                )
                .unwrap(),
            FencedFailureFinalizeResult::RetryScheduled {
                next_attempt_at_millis: 30_000,
            }
        );

        assert!(storage
            .claim_one_fenced_vector_sync("generation-b", "descriptor-a", 2, "worker-a")
            .unwrap()
            .is_none());
        let retry = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(retry.generation_id(), "generation-a");
        let durable = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(durable.attempt_count, 1);
        assert_eq!(
            durable.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
        assert_eq!(
            durable.last_send_disposition.as_deref(),
            Some("definitely_not_sent")
        );

        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let replacement = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(replacement.attempt_count, 0);
        assert_eq!(replacement.claimed_generation_id, None);
        assert_eq!(replacement.last_send_disposition, None);
    }

    #[test]
    fn claim_one_fenced_vector_sync_quarantines_generation_binding_invariants() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET state='pending', attempt_count=1, claimed_generation_id=NULL
                     WHERE life_id='life' AND memory_id=?1",
                    params![record.id],
                )
                .unwrap();
        }
        assert!(storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .is_none());
        let missing = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(missing.state, "blocked");
        assert_eq!(
            missing.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );
        assert_eq!(missing.attempt_count, 1);
        assert_eq!(missing.claimed_generation_id, None);

        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET attempt_count=0, claimed_generation_id='generation-a', state='pending'
                     WHERE life_id='life' AND memory_id=?1",
                    params![record.id],
                )
                .unwrap();
        }
        assert!(storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .is_none());
        let invalid = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(invalid.state, "blocked");
        assert_eq!(
            invalid.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );
        assert_eq!(invalid.attempt_count, 0);
        assert_eq!(
            invalid.claimed_generation_id.as_deref(),
            Some("generation-a")
        );

        {
            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET claimed_generation_id=NULL,
                         migration_disposition='legacy_upsert_rebuild_required'
                     WHERE life_id='life' AND memory_id=?1",
                    params![record.id],
                )
                .unwrap();
        }
        assert!(storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .is_none());
        let isolated = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(
            isolated.migration_disposition.as_deref(),
            Some("legacy_upsert_rebuild_required")
        );
        assert_eq!(isolated.state, "blocked");
    }

    #[test]
    fn mark_fenced_attempt_started_keeps_generation_binding_durable() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(
            storage.mark_fenced_attempt_started(&claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        let snapshot = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(snapshot.attempt_count, 1);
        assert_eq!(
            snapshot.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
    }

    #[test]
    fn generation_binding_failure_finalize_releases_only_pre_attempt_ephemeral_binding() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let pre_attempt = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        assert_eq!(
            storage
                .block_fenced_vector_target_stale(&pre_attempt)
                .unwrap(),
            FencedFinalizeResult::Applied
        );
        let released = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(released.attempt_count, 0);
        assert_eq!(released.claimed_generation_id, None);

        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: record.life_id.clone(),
                memory_id: record.id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let post_attempt = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        storage.mark_fenced_attempt_started(&post_attempt).unwrap();
        assert_eq!(
            storage
                .test_complete_claim_via_real_reserved_token(
                    &post_attempt,
                    None,
                    Some("VECTOR_TARGET_STALE"),
                    false,
                    Some("definitely_not_sent"),
                )
                .unwrap(),
            FencedFinalizeResult::Applied
        );
        let retained = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(retained.attempt_count, 1);
        assert_eq!(
            retained.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
    }

    #[test]
    fn recover_expired_generation_binding_releases_ephemeral_and_preserves_durable() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let first = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        let mut state = storage.state().unwrap();
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            recover_expired_fenced_processing_in(&tx, Some(0)).unwrap(),
            0
        );
        tx.commit().unwrap();
        drop(state);
        let unexpired = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(unexpired.state, "processing");
        assert_eq!(unexpired.attempt_count, 0);
        assert_eq!(
            unexpired.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
        storage.test_expire_fenced_runtime_lease().unwrap();
        let mut state = storage.state().unwrap();
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            recover_expired_fenced_processing_in(&tx, Some(1_700_000_000_000)).unwrap(),
            1
        );
        tx.commit().unwrap();
        drop(state);
        let ephemeral = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(ephemeral.attempt_count, 0);
        assert_eq!(ephemeral.claimed_generation_id, None);

        let durable_claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-b")
            .unwrap()
            .unwrap();
        assert_eq!(
            storage.mark_fenced_attempt_started(&durable_claim).unwrap(),
            FencedAttemptStartResult::Started { attempt_count: 1 }
        );
        storage.test_expire_fenced_runtime_lease().unwrap();
        let mut state = storage.state().unwrap();
        let tx = state
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(
            recover_expired_fenced_processing_in(&tx, Some(1_700_000_000_000)).unwrap(),
            1
        );
        tx.commit().unwrap();
        drop(state);
        let durable = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(durable.attempt_count, 1);
        assert_eq!(
            durable.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
        assert_eq!(durable.state, "blocked");
        drop(first);
    }

    #[test]
    fn retry_failures_preserves_durable_generation_binding_and_excludes_unknown_send() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        storage.mark_fenced_attempt_started(&claim).unwrap();
        storage
            .test_fail_claim_via_real_reserved_token(
                &claim,
                "RATE_LIMITED",
                FencedFailureDecision::Blocked,
                Some("definitely_not_sent"),
                0,
                0,
            )
            .unwrap();
        assert_eq!(storage.retry_failures("life").unwrap(), 1);
        let retried = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(retried.state, "pending");
        assert_eq!(retried.attempt_count, 1);
        assert_eq!(
            retried.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
        assert_eq!(
            retried.last_send_disposition.as_deref(),
            Some("definitely_not_sent")
        );

        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state='blocked', last_send_disposition='possibly_sent',
                     last_error_code='PROVIDER_RESULT_UNKNOWN'
                 WHERE life_id='life' AND memory_id=?1",
                params![record.id],
            )
            .unwrap();
        assert_eq!(storage.retry_failures("life").unwrap(), 0);
        let unknown = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(unknown.state, "blocked");
        assert_eq!(unknown.attempt_count, 1);
        assert_eq!(
            unknown.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
    }

    #[test]
    fn generation_binding_invariant_quarantines_operational_and_manual_retry_rows() {
        let (_root, storage) = storage();
        let record = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let database = crate::storage::open_authorized_test_connection(
            &storage.test_database_main_path().unwrap(),
        )
        .unwrap();

        database
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state='pending', attempt_count=1, claimed_generation_id=NULL,
                     lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL
                 WHERE life_id=?1 AND memory_id=?2",
                params![record.life_id, record.id],
            )
            .unwrap();
        assert!(storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .is_none());
        let pending_missing = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(pending_missing.state, "blocked");
        assert_eq!(
            pending_missing.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );
        assert_eq!(pending_missing.attempt_count, 1);
        assert_eq!(pending_missing.claimed_generation_id, None);

        database
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state='retry_wait', attempt_count=1, claimed_generation_id=NULL,
                     next_attempt_at=NULL
                 WHERE life_id=?1 AND memory_id=?2",
                params![record.life_id, record.id],
            )
            .unwrap();
        assert_eq!(storage.retry_failures("life").unwrap(), 1);
        let retry_missing = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(retry_missing.state, "blocked");
        assert_eq!(
            retry_missing.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );
        assert_eq!(retry_missing.attempt_count, 1);
        assert_eq!(retry_missing.claimed_generation_id, None);

        database
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state='blocked', attempt_count=0, claimed_generation_id='generation-a',
                     lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL
                 WHERE life_id=?1 AND memory_id=?2",
                params![record.life_id, record.id],
            )
            .unwrap();
        assert_eq!(storage.retry_failures("life").unwrap(), 1);
        let invalid_pre_attempt = storage
            .test_get_outbox_snapshot_detailed("life", &record.id)
            .unwrap();
        assert_eq!(invalid_pre_attempt.state, "blocked");
        assert_eq!(
            invalid_pre_attempt.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );
        assert_eq!(invalid_pre_attempt.attempt_count, 0);
        assert_eq!(
            invalid_pre_attempt.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
    }

    #[test]
    fn claim_quarantine_is_visible_through_production_outbox_health_api() {
        let (_root, storage) = storage();
        let operational = confirmed(&storage, false);
        let isolated = confirmed(&storage, false);
        let unknown_send = confirmed(&storage, false);
        storage
            .register_building_vector_generation("generation-a", "descriptor-a", 2)
            .unwrap();
        let database = crate::storage::open_authorized_test_connection(
            &storage.test_database_main_path().unwrap(),
        )
        .unwrap();
        database
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state='pending', attempt_count=1, claimed_generation_id=NULL,
                     lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL
                 WHERE life_id=?1 AND memory_id=?2",
                params![operational.life_id, operational.id],
            )
            .unwrap();
        database
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state='pending', attempt_count=1, claimed_generation_id=NULL,
                     lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL,
                     migration_disposition='legacy_upsert_rebuild_required'
                 WHERE life_id=?1 AND memory_id=?2",
                params![isolated.life_id, isolated.id],
            )
            .unwrap();
        database
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state='blocked', attempt_count=1, claimed_generation_id='generation-a',
                     lease_owner=NULL, lease_fence_epoch=NULL, lease_expires_at=NULL,
                     last_send_disposition='possibly_sent', last_error_code='PROVIDER_RESULT_UNKNOWN'
                 WHERE life_id=?1 AND memory_id=?2",
                params![unknown_send.life_id, unknown_send.id],
            )
            .unwrap();

        let before = storage
            .inspect_outbox_sync_health("generation-a", 3, 0)
            .unwrap();
        assert_eq!(before.pending_count, 1);
        assert_eq!(before.blocked_count, 1);
        assert_eq!(before.internal_invariant_count, 0);
        assert_eq!(before.provider_result_unknown_count, 1);

        assert!(storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .is_none());

        let after = storage
            .inspect_outbox_sync_health("generation-a", 3, 0)
            .unwrap();
        assert_eq!(after.pending_count, 0);
        assert_eq!(after.blocked_count, 2);
        assert_eq!(after.internal_invariant_count, 1);
        assert_eq!(after.provider_result_unknown_count, 1);

        let isolated_after = storage
            .test_get_outbox_snapshot_detailed(&isolated.life_id, &isolated.id)
            .unwrap();
        assert_eq!(isolated_after.state, "pending");
        assert_eq!(isolated_after.attempt_count, 1);
        assert_eq!(isolated_after.claimed_generation_id, None);
        assert_eq!(
            isolated_after.migration_disposition.as_deref(),
            Some("legacy_upsert_rebuild_required")
        );
        let unknown_after = storage
            .test_get_outbox_snapshot_detailed(&unknown_send.life_id, &unknown_send.id)
            .unwrap();
        assert_eq!(unknown_after.state, "blocked");
        assert_eq!(
            unknown_after.last_error_code.as_deref(),
            Some("PROVIDER_RESULT_UNKNOWN")
        );
        assert_eq!(
            unknown_after.last_send_disposition.as_deref(),
            Some("possibly_sent")
        );
    }

    #[test]
    fn generation_binding_two_connections_claim_at_most_once_for_ten_rounds() {
        for round in 0..10 {
            let (root, first) = storage();
            confirmed(&first, false);
            first
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let first_barrier = Arc::clone(&barrier);
            let first_thread = thread::spawn(move || {
                first_barrier.wait();
                first.claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            });
            let second_thread = thread::spawn(move || {
                barrier.wait();
                second.claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-b")
            });
            let first_claim = first_thread.join().unwrap();
            let second_claim = second_thread.join().unwrap();
            assert_eq!(
                usize::from(matches!(first_claim, Ok(Some(_))))
                    + usize::from(matches!(second_claim, Ok(Some(_)))),
                1,
                "round {round}"
            );
        }
    }

    #[test]
    fn generation_binding_recovery_and_retry_compete_for_ten_rounds() {
        for round in 0..10 {
            let (root, first) = storage();
            let record = confirmed(&first, false);
            first
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let claim = first
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            assert_eq!(
                first.mark_fenced_attempt_started(&claim).unwrap(),
                FencedAttemptStartResult::Started { attempt_count: 1 }
            );
            first.test_expire_fenced_runtime_lease().unwrap();
            let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let barrier = Arc::new(Barrier::new(2));
            let first_barrier = Arc::clone(&barrier);
            let recovery = thread::spawn(move || {
                first_barrier.wait();
                first.test_recover_expired_fenced_processing_for_generation_binding(
                    1_700_000_000_000,
                )
            });
            let retry = thread::spawn(move || {
                barrier.wait();
                second.retry_failures("life")
            });
            recovery.join().unwrap().unwrap();
            retry.join().unwrap().unwrap();

            let verifier =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let snapshot = verifier
                .test_get_outbox_snapshot_detailed("life", &record.id)
                .unwrap();
            assert_eq!(snapshot.attempt_count, 1, "round {round}");
            assert_eq!(
                snapshot.claimed_generation_id.as_deref(),
                Some("generation-a"),
                "round {round}"
            );
            assert!(
                matches!(snapshot.state.as_str(), "blocked" | "pending"),
                "round {round}"
            );
        }
    }

    #[test]
    fn generation_binding_invariant_stale_cas_preserves_real_new_mutation_for_ten_rounds() {
        for round in 0..10 {
            let (root, first) = storage();
            let record = confirmed(&first, false);
            first
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let claim = first
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            let old = first
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap();
            let old_revision = old.target_revision.expect("upsert target revision");
            let old_hash = old.target_content_hash.clone().expect("upsert target hash");
            first
                .state()
                .unwrap()
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET claimed_generation_id=NULL
                     WHERE life_id=?1 AND memory_id=?2",
                    params![record.life_id, record.id],
                )
                .unwrap();
            let expected = {
                let mut state = first.state().unwrap();
                let transaction = state
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                let row = generation_binding_row_for_claim_in(&transaction, &claim)
                    .unwrap()
                    .unwrap();
                assert_eq!(
                    row.phase(),
                    GenerationBindingPhase::Invalid,
                    "round {round}"
                );
                transaction.commit().unwrap();
                row
            };
            let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let (committed_tx, committed_rx) = mpsc::sync_channel(0);
            let replacement_life_id = record.life_id.clone();
            let replacement_memory_id = record.id.clone();
            let replacement = thread::spawn(move || {
                let update = MemoryRevisionService::new(&second)
                    .update_confirmed(UpdateConfirmedMemoryRequest {
                        life_id: replacement_life_id,
                        memory_id: replacement_memory_id,
                        expected_revision: old_revision,
                        kind: MemoryKind::Fact,
                        content: format!("replacement content {round}"),
                        summary: Some(format!("replacement summary {round}")),
                    })
                    .unwrap();
                assert!(update.revision > old_revision, "round {round}");
                committed_tx.send(()).unwrap();
            });
            let stale_block = thread::spawn(move || {
                committed_rx.recv().unwrap();
                let mut state = first.state().unwrap();
                let transaction = state
                    .connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                let outcome =
                    block_generation_binding_scan_snapshot_in(&transaction, &expected).unwrap();
                transaction.commit().unwrap();
                outcome
            });
            replacement.join().unwrap();
            assert_eq!(
                stale_block.join().unwrap(),
                InvariantBlockOutcome::Superseded,
                "round {round}"
            );

            let verifier =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let snapshot = verifier
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap();
            assert_eq!(snapshot.state, "pending", "round {round}");
            assert!(
                snapshot.mutation_sequence > old.mutation_sequence,
                "round {round}"
            );
            assert!(
                snapshot.target_revision.expect("new target revision") > old_revision,
                "round {round}"
            );
            assert_ne!(
                snapshot.target_content_hash.as_deref(),
                Some(old_hash.as_str()),
                "round {round}"
            );
            assert_eq!(snapshot.attempt_count, 0, "round {round}");
            assert_eq!(snapshot.claimed_generation_id, None, "round {round}");
            assert_eq!(snapshot.lease_owner, None, "round {round}");
            assert_eq!(snapshot.lease_fence_epoch, None, "round {round}");
            assert_eq!(snapshot.lease_expires_at, None, "round {round}");
            assert_eq!(snapshot.last_error_code, None, "round {round}");
            assert_eq!(snapshot.last_send_disposition, None, "round {round}");
        }
    }

    /// `retry_failures` is a second entry point into durable attempt state, so it
    /// must converge an at-limit retry row and quarantine an over-budget failed row
    /// rather than reopening either of them.
    #[test]
    fn retry_failures_converges_attempt_limit_and_preserves_terminal_errors() {
        let (_root, storage) = storage();
        let fifth_claim = claim_before_final_attempt_slot(&storage);
        let memory_id = fifth_claim.memory_id().to_owned();
        assert_eq!(
            storage
                .reserve_fenced_attempt(&fifth_claim)
                .unwrap()
                .ordinal(),
            Some(MAX_VECTOR_SYNC_ATTEMPTS)
        );
        assert_eq!(
            storage
                .test_fail_claim_via_real_reserved_token(
                    &fifth_claim,
                    "INVALID_REQUEST",
                    FencedFailureDecision::RetryAfter { delay_millis: 1 },
                    Some("definitely_not_sent"),
                    0,
                    0,
                )
                .unwrap(),
            FencedFailureFinalizeResult::RetryScheduled {
                next_attempt_at_millis: 1
            }
        );
        assert_eq!(storage.retry_failures("life").unwrap(), 1);
        let at_limit = storage
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(at_limit.state, "blocked");
        assert_eq!(at_limit.attempt_count, MAX_VECTOR_SYNC_ATTEMPTS);
        assert_eq!(
            at_limit.last_error_code.as_deref(),
            Some("INVALID_REQUEST"),
            "a stable permanent error outranks MAX_ATTEMPTS"
        );
        assert_eq!(
            at_limit.claimed_generation_id.as_deref(),
            Some("generation-a")
        );
        assert_eq!(
            attempt_epochs(&storage, &memory_id),
            (
                fifth_claim.fenced_claim_epoch(),
                fifth_claim.fenced_claim_epoch()
            )
        );
        assert_eq!(
            storage.retry_failures("life").unwrap(),
            0,
            "a terminal count-five row is not converged twice"
        );

        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: memory_id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let internal_claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        storage.reserve_fenced_attempt(&internal_claim).unwrap();
        storage
            .test_fail_claim_via_real_reserved_token(
                &internal_claim,
                "INTERNAL_INVARIANT",
                FencedFailureDecision::Blocked,
                Some("definitely_not_sent"),
                0,
                0,
            )
            .unwrap();
        assert_eq!(
            storage.retry_failures("life").unwrap(),
            0,
            "manual retry must not reopen an INTERNAL_INVARIANT row"
        );
        let internal = storage
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(internal.state, "blocked");
        assert_eq!(internal.attempt_count, 1);
        assert_eq!(
            internal.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );

        storage
            .enqueue(EnqueueMemoryVectorSyncRequest {
                life_id: "life".into(),
                memory_id: memory_id.clone(),
                desired_action: MemoryVectorSyncAction::Upsert,
            })
            .unwrap();
        let over_budget_claim = storage
            .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
            .unwrap()
            .unwrap();
        storage
            .state()
            .unwrap()
            .connection
            .execute(
                "UPDATE memory_vector_sync_outbox
                 SET state='failed', attempt_count=6,
                     fenced_claim_epoch=?1, last_marked_claim_epoch=?1,
                     lease_owner=NULL, lease_fence_epoch=NULL,
                     lease_expires_at=NULL, next_attempt_at=NULL,
                     last_error_code='PROVIDER_UNAVAILABLE'
                 WHERE id=?2",
                params![
                    over_budget_claim.fenced_claim_epoch(),
                    over_budget_claim.id()
                ],
            )
            .unwrap();
        assert_eq!(storage.retry_failures("life").unwrap(), 1);
        let over_budget = storage
            .test_get_outbox_snapshot_detailed("life", &memory_id)
            .unwrap();
        assert_eq!(over_budget.state, "blocked");
        assert_eq!(over_budget.attempt_count, 6);
        assert_eq!(
            over_budget.last_error_code.as_deref(),
            Some("INTERNAL_INVARIANT")
        );
    }

    /// Covers recovery states that cannot be inferred from ordinary worker tests:
    /// an unmarked durable claim, a marked delete at the fifth slot, and a schema-13
    /// `(0, 0)` processing row that must never materialize an Attempt token.
    #[test]
    fn recover_expired_attempt_identity_preserves_unmarked_marked_and_legacy_evidence() {
        {
            let (_root, storage) = storage();
            let first = claimed_upsert(&storage);
            assert_eq!(
                storage.reserve_fenced_attempt(&first).unwrap().ordinal(),
                Some(1)
            );
            assert_eq!(
                storage
                    .test_fail_claim_via_real_reserved_token(
                        &first,
                        "PROVIDER_UNAVAILABLE",
                        FencedFailureDecision::RetryAfter { delay_millis: 1 },
                        Some("definitely_not_sent"),
                        0,
                        0,
                    )
                    .unwrap(),
                FencedFailureFinalizeResult::RetryScheduled {
                    next_attempt_at_millis: 1
                }
            );
            let unmarked = storage
                .claim_one_fenced_vector_sync_with_retry_cutoff(
                    "generation-a",
                    "descriptor-a",
                    2,
                    "worker-a",
                    Some(60_000),
                )
                .unwrap()
                .unwrap();
            assert_eq!(attempt_epochs(&storage, unmarked.memory_id()), (2, 1));
            storage.test_expire_fenced_runtime_lease().unwrap();
            assert_eq!(
                storage
                    .test_recover_expired_fenced_processing_for_generation_binding(
                        1_700_000_000_000
                    )
                    .unwrap(),
                1
            );
            let recovered = storage
                .test_get_outbox_snapshot_detailed("life", unmarked.memory_id())
                .unwrap();
            assert_eq!(recovered.state, "pending");
            assert_eq!(recovered.attempt_count, 1);
            assert_eq!(
                recovered.claimed_generation_id.as_deref(),
                Some("generation-a"),
                "an unmarked current claim must keep the earlier durable binding"
            );
            assert_eq!(
                recovered.last_send_disposition.as_deref(),
                Some("definitely_not_sent")
            );
            assert_eq!(
                recovered.last_error_code.as_deref(),
                Some("PROVIDER_UNAVAILABLE")
            );
            assert_eq!(attempt_epochs(&storage, unmarked.memory_id()), (2, 1));
            assert_eq!(recovered.lease_owner, None);
            assert_eq!(recovered.lease_fence_epoch, None);
            assert_eq!(recovered.lease_expires_at, None);
        }

        {
            let (_root, storage) = storage();
            let record = confirmed(&storage, false);
            storage
                .enqueue(EnqueueMemoryVectorSyncRequest {
                    life_id: record.life_id.clone(),
                    memory_id: record.id.clone(),
                    desired_action: MemoryVectorSyncAction::Delete,
                })
                .unwrap();
            storage
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let delete = storage
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            storage
                .test_set_fenced_attempt_count(MAX_VECTOR_SYNC_ATTEMPTS)
                .unwrap();
            storage.test_expire_fenced_runtime_lease().unwrap();
            assert_eq!(
                storage
                    .test_recover_expired_fenced_processing_for_generation_binding(
                        1_700_000_000_000
                    )
                    .unwrap(),
                1
            );
            let recovered = storage
                .test_get_outbox_snapshot_detailed("life", delete.memory_id())
                .unwrap();
            assert_eq!(recovered.state, "blocked");
            assert_eq!(recovered.attempt_count, MAX_VECTOR_SYNC_ATTEMPTS);
            assert_eq!(recovered.last_error_code.as_deref(), Some("MAX_ATTEMPTS"));
            assert_eq!(recovered.last_send_disposition, None);
            assert_eq!(
                recovered.claimed_generation_id.as_deref(),
                Some("generation-a")
            );
            assert_eq!(
                attempt_epochs(&storage, delete.memory_id()),
                (delete.fenced_claim_epoch(), delete.fenced_claim_epoch())
            );
            assert_eq!(recovered.lease_owner, None);
            assert_eq!(recovered.lease_fence_epoch, None);
            assert_eq!(recovered.lease_expires_at, None);
        }

        {
            let (_root, storage) = storage();
            let record = confirmed(&storage, false);
            storage
                .enqueue(EnqueueMemoryVectorSyncRequest {
                    life_id: record.life_id.clone(),
                    memory_id: record.id.clone(),
                    desired_action: MemoryVectorSyncAction::Delete,
                })
                .unwrap();
            storage
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let claim = storage
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            storage
                .state()
                .unwrap()
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET fenced_claim_epoch=0, last_marked_claim_epoch=0
                     WHERE id=?1",
                    params![claim.id()],
                )
                .unwrap();
            let legacy_claim = FencedVectorSyncClaim {
                fenced_claim_epoch: 0,
                ..copy_fenced_claim_for_test(&claim)
            };
            assert!(
                storage
                    .reserve_fenced_attempt(&legacy_claim)
                    .unwrap()
                    .is_lost(),
                "a schema-13 claim identity may not manufacture a token"
            );
            storage.test_expire_fenced_runtime_lease().unwrap();
            assert_eq!(
                storage
                    .test_recover_expired_fenced_processing_for_generation_binding(
                        1_700_000_000_000
                    )
                    .unwrap(),
                1
            );
            let recovered = storage
                .test_get_outbox_snapshot_detailed("life", claim.memory_id())
                .unwrap();
            assert_eq!(recovered.state, "pending");
            assert_eq!(recovered.attempt_count, 0);
            assert_eq!(recovered.claimed_generation_id, None);
            assert_eq!(attempt_epochs(&storage, claim.memory_id()), (0, 0));
            assert_eq!(recovered.lease_owner, None);
            assert_eq!(recovered.lease_fence_epoch, None);
            assert_eq!(recovered.lease_expires_at, None);
        }
    }

    /// The final slot is contended by an old claim and a fresh claim from two
    /// independent StorageService instances. The old claim is deliberately
    /// superseded by lease takeover, so a single distinct claim identity may
    /// produce the fifth token and the stale identity cannot turn it into six.
    #[test]
    fn attempt_claim_last_slot_competition_uses_one_token_for_ten_rounds() {
        for round in 0..10 {
            let (root, first) = storage();
            let stale_claim = claim_before_final_attempt_slot(&first);
            let memory_id = stale_claim.memory_id().to_owned();
            assert_eq!(
                first
                    .test_get_outbox_snapshot_detailed("life", &memory_id)
                    .unwrap()
                    .attempt_count,
                MAX_VECTOR_SYNC_ATTEMPTS - 1,
                "round {round} must start at the final available slot"
            );

            first.test_expire_fenced_runtime_lease().unwrap();
            let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let current_claim = second
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-b")
                .unwrap()
                .expect("the final slot remains eligible after lease takeover");
            assert!(
                current_claim.fenced_claim_epoch() > stale_claim.fenced_claim_epoch(),
                "round {round} must grant the new claim a distinct epoch"
            );

            let stale_for_reserve = copy_fenced_claim_for_test(&stale_claim);
            let current_for_reserve = copy_fenced_claim_for_test(&current_claim);
            let barrier = Arc::new(Barrier::new(2));
            let stale_barrier = Arc::clone(&barrier);
            let stale_thread = thread::spawn(move || {
                stale_barrier.wait();
                first.reserve_fenced_attempt(&stale_for_reserve)
            });
            let current_thread = thread::spawn(move || {
                barrier.wait();
                second.reserve_fenced_attempt(&current_for_reserve)
            });

            let stale_result = stale_thread.join().unwrap().unwrap();
            let current_result = current_thread.join().unwrap().unwrap();
            assert!(
                stale_result.is_lost(),
                "round {round}: a superseded claim may not reserve the last slot"
            );
            let token = current_result
                .token()
                .expect("the current claim alone receives the final token");
            assert_eq!(token.attempt_ordinal(), MAX_VECTOR_SYNC_ATTEMPTS);

            let verifier =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let snapshot = verifier
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap();
            assert_eq!(snapshot.state, "processing", "round {round}");
            assert_eq!(
                snapshot.attempt_count, MAX_VECTOR_SYNC_ATTEMPTS,
                "round {round}: only one 4-to-5 transition is possible"
            );
            assert_eq!(
                attempt_epochs(&verifier, &memory_id),
                (
                    current_claim.fenced_claim_epoch(),
                    current_claim.fenced_claim_epoch()
                ),
                "round {round}: the unique final token is fully marked"
            );
            assert_eq!(
                snapshot.claimed_generation_id.as_deref(),
                Some("generation-a"),
                "round {round}: final-slot contention cannot drop the durable binding"
            );
            assert!(
                verifier
                    .validate_fenced_attempt_token_current(token)
                    .unwrap(),
                "round {round}: the sole returned token must be current"
            );
        }
    }

    /// Recovery receives an artificial future cutoff while reserve uses the real
    /// clock. That makes both operations contend for one row without a sleep: if
    /// reserve wins, recovery sees a marked possibly-sent upsert and blocks it; if
    /// recovery wins, reserve sees the released old claim and cannot increment.
    #[test]
    fn recover_expired_mark_competition_preserves_attempt_identity_for_ten_rounds() {
        const FAR_FUTURE_EXPIRY: &str = "9999-12-31T23:59:59.999Z";
        const FAR_FUTURE_CUTOFF_MILLIS: i64 = 253_402_300_799_999;

        for round in 0..10 {
            let (root, first) = storage();
            let claim = claimed_upsert(&first);
            let memory_id = claim.memory_id().to_owned();
            first
                .state()
                .unwrap()
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET lease_expires_at=?1 WHERE id=?2",
                    params![FAR_FUTURE_EXPIRY, claim.id()],
                )
                .unwrap();

            let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let mark_claim = copy_fenced_claim_for_test(&claim);
            let barrier = Arc::new(Barrier::new(2));
            let recovery_barrier = Arc::clone(&barrier);
            let recovery = thread::spawn(move || {
                recovery_barrier.wait();
                first.test_recover_expired_fenced_processing_for_generation_binding(
                    FAR_FUTURE_CUTOFF_MILLIS,
                )
            });
            let mark = thread::spawn(move || {
                barrier.wait();
                second.reserve_fenced_attempt(&mark_claim)
            });

            assert_eq!(recovery.join().unwrap().unwrap(), 1, "round {round}");
            let mark_result = mark.join().unwrap().unwrap();
            let verifier =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let snapshot = verifier
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap();

            match mark_result {
                FencedAttemptReservation::Reserved(token) => {
                    assert_eq!(token.attempt_ordinal(), 1, "round {round}");
                    assert_eq!(snapshot.state, "blocked", "round {round}");
                    assert_eq!(snapshot.attempt_count, 1, "round {round}");
                    assert_eq!(
                        snapshot.claimed_generation_id.as_deref(),
                        Some("generation-a"),
                        "round {round}: recovery must not drop a durable binding"
                    );
                    assert_eq!(
                        snapshot.last_send_disposition.as_deref(),
                        Some("possibly_sent"),
                        "round {round}"
                    );
                    assert_eq!(
                        snapshot.last_error_code.as_deref(),
                        Some("PROVIDER_RESULT_UNKNOWN"),
                        "round {round}: an unknown upsert must never reopen"
                    );
                    assert_eq!(attempt_epochs(&verifier, &memory_id), (1, 1));
                }
                FencedAttemptReservation::LostLeaseOrSuperseded => {
                    assert_eq!(snapshot.state, "pending", "round {round}");
                    assert_eq!(snapshot.attempt_count, 0, "round {round}");
                    assert_eq!(snapshot.claimed_generation_id, None, "round {round}");
                    assert_eq!(snapshot.last_send_disposition, None, "round {round}");
                    assert_eq!(snapshot.last_error_code, None, "round {round}");
                    assert_eq!(attempt_epochs(&verifier, &memory_id), (1, 0));
                }
                FencedAttemptReservation::BudgetExhausted => {
                    panic!("round {round}: a zero-count claim cannot exhaust the budget")
                }
            }
            assert_eq!(snapshot.lease_owner, None, "round {round}");
            assert_eq!(snapshot.lease_fence_epoch, None, "round {round}");
            assert_eq!(snapshot.lease_expires_at, None, "round {round}");
        }
    }

    /// A real mutation transaction races an old reserve transaction from a second
    /// StorageService. Whichever commits first, the new mutation is the only final
    /// budget authority and the old claim is stale when checked after both commits.
    #[test]
    fn new_mutation_old_mark_race_cannot_spend_replacement_budget_for_ten_rounds() {
        for round in 0..10 {
            let (root, first) = storage();
            let record = confirmed(&first, false);
            first
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            let old_claim = first
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            let before = first
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap();
            let old_revision = before.target_revision.expect("old upsert revision");
            let old_hash = before.target_content_hash.clone().expect("old upsert hash");

            let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let mark_claim = copy_fenced_claim_for_test(&old_claim);
            let barrier = Arc::new(Barrier::new(2));
            let mark_barrier = Arc::clone(&barrier);
            let mark = thread::spawn(move || {
                mark_barrier.wait();
                first.reserve_fenced_attempt(&mark_claim)
            });
            let life_id = record.life_id.clone();
            let memory_id = record.id.clone();
            let replacement = thread::spawn(move || {
                barrier.wait();
                MemoryRevisionService::new(&second).update_confirmed(UpdateConfirmedMemoryRequest {
                    life_id,
                    memory_id,
                    expected_revision: old_revision,
                    kind: MemoryKind::Fact,
                    content: format!("ATT-I2 replacement content {round}"),
                    summary: Some(format!("ATT-I2 replacement summary {round}")),
                })
            });

            let mark_result = mark.join().unwrap().unwrap();
            let replacement = replacement.join().unwrap().unwrap();
            assert!(replacement.revision > old_revision, "round {round}");
            match mark_result {
                FencedAttemptReservation::Reserved(token) => {
                    assert_eq!(token.attempt_ordinal(), 1, "round {round}");
                }
                FencedAttemptReservation::LostLeaseOrSuperseded => {}
                FencedAttemptReservation::BudgetExhausted => {
                    panic!("round {round}: a pre-mutation first claim cannot exhaust the budget")
                }
            }

            let verifier =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let snapshot = verifier
                .test_get_outbox_snapshot_detailed(&record.life_id, &record.id)
                .unwrap();
            assert_eq!(snapshot.state, "pending", "round {round}");
            assert!(
                snapshot.mutation_sequence > before.mutation_sequence,
                "round {round}: the replacement must own a new budget key"
            );
            assert!(
                snapshot.target_revision.expect("replacement revision") > old_revision,
                "round {round}"
            );
            assert_ne!(
                snapshot.target_content_hash.as_deref(),
                Some(old_hash.as_str()),
                "round {round}"
            );
            assert_eq!(snapshot.attempt_count, 0, "round {round}");
            assert_eq!(attempt_epochs(&verifier, &record.id), (0, 0));
            assert_eq!(snapshot.claimed_generation_id, None, "round {round}");
            assert_eq!(snapshot.last_send_disposition, None, "round {round}");
            assert_eq!(snapshot.last_error_code, None, "round {round}");
            assert_eq!(snapshot.lease_owner, None, "round {round}");
            assert_eq!(snapshot.lease_fence_epoch, None, "round {round}");
            assert_eq!(snapshot.lease_expires_at, None, "round {round}");
            assert_eq!(snapshot.next_attempt_at, None, "round {round}");
            assert_eq!(snapshot.migration_disposition, None, "round {round}");
            assert!(
                verifier
                    .reserve_fenced_attempt(&old_claim)
                    .unwrap()
                    .is_lost(),
                "round {round}: an old claim cannot spend the replacement budget"
            );
        }
    }

    /// A reclaimed row may reuse its owner and runtime fence, but its new claim
    /// epoch is a separate authority. Old current/finalize calls race a real
    /// second connection observing the new `processing` claim; neither old call
    /// may write the new row.
    #[test]
    fn stale_same_owner_claim_epoch_competition_preserves_new_claim_for_ten_rounds() {
        for round in 0..10 {
            let (root, first) = storage();
            let (old_claim, current_claim) = same_owner_same_fence_epoch_pair(&first);
            let memory_id = current_claim.memory_id().to_owned();
            let before = first
                .test_get_outbox_snapshot_detailed("life", &memory_id)
                .unwrap();
            let second = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            let stale_claim = copy_fenced_claim_for_test(&old_claim);
            let current_claim_for_thread = copy_fenced_claim_for_test(&current_claim);
            let barrier = Arc::new(Barrier::new(2));
            let stale_barrier = Arc::clone(&barrier);
            let stale = thread::spawn(move || {
                stale_barrier.wait();
                let current = first.fenced_vector_claim_is_current(&stale_claim).unwrap();
                let success = first
                    .test_complete_claim_via_real_reserved_token(
                        &stale_claim,
                        Some("old-epoch-content-hash"),
                        None,
                        false,
                        None,
                    )
                    .unwrap();
                let failure = first
                    .test_fail_claim_via_real_reserved_token(
                        &stale_claim,
                        "PROVIDER_UNAVAILABLE",
                        FencedFailureDecision::Blocked,
                        Some("definitely_not_sent"),
                        0,
                        0,
                    )
                    .unwrap();
                (current, success, failure)
            });
            let current = thread::spawn(move || {
                barrier.wait();
                second
                    .fenced_vector_claim_is_current(&current_claim_for_thread)
                    .unwrap()
            });

            let (old_is_current, old_success, old_failure) = stale.join().unwrap();
            assert!(!old_is_current, "round {round}: old epoch is not current");
            assert_eq!(
                old_success,
                FencedFinalizeResult::LostLeaseOrSuperseded,
                "round {round}: old epoch cannot success-finalize"
            );
            assert_eq!(
                old_failure,
                FencedFailureFinalizeResult::LostLeaseOrSuperseded,
                "round {round}: old epoch cannot failure-finalize"
            );
            assert!(
                current.join().unwrap(),
                "round {round}: new epoch remains current"
            );

            let verifier =
                StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
            assert_eq!(
                verifier
                    .test_get_outbox_snapshot_detailed("life", &memory_id)
                    .unwrap(),
                before,
                "round {round}: old epoch must not mutate the new claim"
            );
            assert!(
                verifier
                    .fenced_vector_claim_is_current(&current_claim)
                    .unwrap(),
                "round {round}: new epoch remains processable"
            );
        }
    }

    /// ATT-I4 full run matrix: every legal action/mark/count/send combination
    /// must converge to the frozen expected state through the real production
    /// recovery path (expired processing + claim-epoch identity).
    #[test]
    fn attempt_recovery_full_run_matrix_converges_to_frozen_states() {
        struct Case {
            name: &'static str,
            action: MemoryVectorSyncAction,
            state_before: &'static str,
            attempt: i64,
            fenced: i64,
            marked: i64,
            send: Option<&'static str>,
            error: Option<&'static str>,
            generation: Option<&'static str>,
            expected_state: &'static str,
            expected_error: Option<&'static str>,
            expected_send: Option<&'static str>,
            expected_attempt: i64,
            expected_generation: Option<&'static str>,
        }

        let cases = [
            // Upsert unmarked claim, attempt 0 (ephemeral binding) → pending, ephemeral generation cleared
            Case {
                name: "upsert-unmarked-0",
                action: MemoryVectorSyncAction::Upsert,
                state_before: "processing",
                attempt: 0,
                fenced: 1,
                marked: 0,
                send: None,
                error: None,
                generation: Some("generation-a"),
                expected_state: "pending",
                expected_error: None,
                expected_send: None,
                expected_attempt: 0,
                expected_generation: None,
            },
            // Upsert unmarked claim, attempt 1-4, definitely_not_sent → pending, keep durable generation
            Case {
                name: "upsert-unmarked-durable",
                action: MemoryVectorSyncAction::Upsert,
                state_before: "processing",
                attempt: 2,
                fenced: 3,
                marked: 2,
                send: Some("definitely_not_sent"),
                error: Some("PROVIDER_UNAVAILABLE"),
                generation: Some("generation-a"),
                expected_state: "pending",
                expected_error: Some("PROVIDER_UNAVAILABLE"),
                expected_send: Some("definitely_not_sent"),
                expected_attempt: 2,
                expected_generation: Some("generation-a"),
            },
            // Upsert marked claim 1-5 possibly_sent → blocked PROVIDER_RESULT_UNKNOWN
            Case {
                name: "upsert-marked-unknown",
                action: MemoryVectorSyncAction::Upsert,
                state_before: "processing",
                attempt: 2,
                fenced: 2,
                marked: 2,
                send: Some("possibly_sent"),
                error: Some("PROVIDER_RESULT_UNKNOWN"),
                generation: Some("generation-a"),
                expected_state: "blocked",
                expected_error: Some("PROVIDER_RESULT_UNKNOWN"),
                expected_send: Some("possibly_sent"),
                expected_attempt: 2,
                expected_generation: Some("generation-a"),
            },
            // Delete unmarked 0 (ephemeral binding) → pending, ephemeral generation cleared
            Case {
                name: "delete-unmarked-0",
                action: MemoryVectorSyncAction::Delete,
                state_before: "processing",
                attempt: 0,
                fenced: 1,
                marked: 0,
                send: None,
                error: None,
                generation: Some("generation-a"),
                expected_state: "pending",
                expected_error: None,
                expected_send: None,
                expected_attempt: 0,
                expected_generation: None,
            },
            // Delete unmarked 1-4 → pending, keep durable generation
            Case {
                name: "delete-unmarked-durable",
                action: MemoryVectorSyncAction::Delete,
                state_before: "processing",
                attempt: 3,
                fenced: 3,
                marked: 1,
                send: None,
                error: Some("LANCE_TRANSIENT"),
                generation: Some("generation-a"),
                expected_state: "pending",
                expected_error: Some("LANCE_TRANSIENT"),
                expected_send: None,
                expected_attempt: 3,
                expected_generation: Some("generation-a"),
            },
            // Delete marked 1-4 → pending (future new attempt possible)
            Case {
                name: "delete-marked-below-limit",
                action: MemoryVectorSyncAction::Delete,
                state_before: "processing",
                attempt: 4,
                fenced: 4,
                marked: 4,
                send: None,
                error: Some("LANCE_TRANSIENT"),
                generation: Some("generation-a"),
                expected_state: "pending",
                expected_error: Some("LANCE_TRANSIENT"),
                expected_send: None,
                expected_attempt: 4,
                expected_generation: Some("generation-a"),
            },
            // Delete marked 5 → blocked MAX_ATTEMPTS
            Case {
                name: "delete-marked-at-limit",
                action: MemoryVectorSyncAction::Delete,
                state_before: "processing",
                attempt: 5,
                fenced: 5,
                marked: 5,
                send: None,
                error: Some("LANCE_TRANSIENT"),
                generation: Some("generation-a"),
                expected_state: "blocked",
                expected_error: Some("MAX_ATTEMPTS"),
                expected_send: None,
                expected_attempt: 5,
                expected_generation: Some("generation-a"),
            },
            // Any > 5 → blocked INTERNAL_INVARIANT
            Case {
                name: "any-over-limit",
                action: MemoryVectorSyncAction::Upsert,
                state_before: "processing",
                attempt: 6,
                fenced: 6,
                marked: 6,
                send: Some("possibly_sent"),
                error: Some("LANCE_PERMANENT"),
                generation: Some("generation-a"),
                expected_state: "blocked",
                expected_error: Some("INTERNAL_INVARIANT"),
                expected_send: Some("possibly_sent"),
                expected_attempt: 6,
                expected_generation: Some("generation-a"),
            },
            // Legacy (0,0) processing with generation binding → conservative blocked convergence
            Case {
                name: "legacy-zero-zero",
                action: MemoryVectorSyncAction::Upsert,
                state_before: "processing",
                attempt: 1,
                fenced: 0,
                marked: 0,
                send: Some("possibly_sent"),
                error: Some("PROVIDER_RESULT_UNKNOWN"),
                generation: Some("generation-a"),
                expected_state: "blocked",
                expected_error: Some("PROVIDER_RESULT_UNKNOWN"),
                expected_send: Some("possibly_sent"),
                expected_attempt: 1,
                expected_generation: Some("generation-a"),
            },
        ];

        for case in cases {
            let (_root, storage) = storage();
            let record = confirmed(&storage, false);
            storage
                .register_building_vector_generation("generation-a", "descriptor-a", 2)
                .unwrap();
            storage
                .enqueue(EnqueueMemoryVectorSyncRequest {
                    life_id: record.life_id.clone(),
                    memory_id: record.id.clone(),
                    desired_action: case.action,
                })
                .unwrap();
            let claim = storage
                .claim_one_fenced_vector_sync("generation-a", "descriptor-a", 2, "worker-a")
                .unwrap()
                .unwrap();
            assert_eq!(claim.action(), case.action);

            let state = storage.state().unwrap();
            state
                .connection
                .execute(
                    "UPDATE memory_vector_sync_outbox
                     SET state=?1, attempt_count=?2, fenced_claim_epoch=?3,
                         last_marked_claim_epoch=?4, last_send_disposition=?5,
                         last_error_code=?6, claimed_generation_id=?7,
                         lease_expires_at='2000-01-01T00:00:00.000Z'
                     WHERE id=?8",
                    params![
                        case.state_before,
                        case.attempt,
                        case.fenced,
                        case.marked,
                        case.send,
                        case.error,
                        case.generation,
                        claim.id(),
                    ],
                )
                .unwrap();
            drop(state);

            storage.test_expire_fenced_runtime_lease().unwrap();
            let recovered = storage
                .test_recover_expired_fenced_processing_for_generation_binding(1_700_000_000_000)
                .unwrap();
            assert_eq!(
                recovered, 1,
                "case {}: exactly one row recovered",
                case.name
            );

            let snap = storage
                .test_get_outbox_snapshot_detailed("life", claim.memory_id())
                .unwrap();
            assert_eq!(snap.state, case.expected_state, "case {}", case.name);
            assert_eq!(
                snap.last_error_code.as_deref(),
                case.expected_error,
                "case {}",
                case.name
            );
            assert_eq!(
                snap.last_send_disposition.as_deref(),
                case.expected_send,
                "case {}",
                case.name
            );
            assert_eq!(
                snap.attempt_count, case.expected_attempt,
                "case {}",
                case.name
            );
            assert_eq!(
                snap.claimed_generation_id.as_deref(),
                case.expected_generation,
                "case {}",
                case.name
            );
            assert_eq!(snap.lease_owner, None, "case {}", case.name);
            assert_eq!(snap.lease_expires_at, None, "case {}", case.name);
        }
    }
}
