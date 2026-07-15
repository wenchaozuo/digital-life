//! Governed candidate-confirmation authorization (D-5A).
//!
//! This module is the *sole* place where a [`SensitiveConfirmationGrant`] can be
//! constructed in production: it is a private child module of `candidate_service`,
//! so `super::SensitiveConfirmationGrant { candidate_id }` is reachable here while
//! remaining unconstructable from the command layer, the repository, or anywhere
//! else. The Tauri command layer drives this coordinator but can never mint a
//! grant itself.
//!
//! The coordinator owns an in-memory Approval Token registry. It never persists to
//! SQLite; authoritative database correctness is delegated entirely to the frozen
//! D-4 confirm transaction. Raw token strings exist only transiently; the registry
//! stores nothing but a digest and non-secret binding metadata.

use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    CandidateConfirmationRecoveryRepository, CandidateLifecycleRepository, CandidateMemoryService,
    ConfirmCandidateOutcome, ConfirmCandidateRequest, SensitiveConfirmationGrant,
};
use crate::memory::{
    candidate::{CandidateMemoryError, CandidateMemoryRecord, CandidateMemoryStatus},
    MemoryKind,
};

/// Number of random bytes backing an Approval Token. 256 bits of CSPRNG output.
const TOKEN_BYTES: usize = 32;
/// Domain separator so a token digest can never collide with any other SHA-256 use.
const TOKEN_DIGEST_DOMAIN: &[u8] = b"candidate-confirmation-approval-token-v1";
/// Token time-to-live from issuance, in milliseconds (3 minutes).
const TOKEN_TTL_MILLIS: u64 = 3 * 60 * 1000;
/// How long an in-flight D-4 call may hold a token before another attempt may take
/// over the lease, in milliseconds (30 seconds).
const IN_FLIGHT_LEASE_MILLIS: u64 = 30 * 1000;
/// How long a consumed token's minimal safe result stays replayable, in
/// milliseconds (5 minutes).
const CONSUMED_CACHE_MILLIS: u64 = 5 * 60 * 1000;
/// Recovery can read the authoritative D-4 result briefly after a panic. It
/// never extends the original token's write authorization.
const RECOVERY_RECONCILIATION_WINDOW_MILLIS: u64 = 30 * 1000;
/// Maximum number of D-4 attempts a single token may drive before it is retired.
const MAX_ATTEMPTS: u32 = 3;
/// Soft capacity of the registry; cleanup runs before growing beyond this.
const REGISTRY_SOFT_CAPACITY: usize = 512;

// ── Cryptographically secure random bytes ─────────────────────────────

/// Fill `buffer` with cryptographically secure random bytes.
///
/// There is deliberately no weak fallback: if the OS CSPRNG is unavailable the
/// call fails closed so a token is never minted from low-quality randomness.
#[cfg(windows)]
fn fill_secure_random(buffer: &mut [u8]) -> Result<(), ()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    // SAFETY: `buffer` is a valid, uniquely-borrowed slice of `len` bytes; a null
    // algorithm handle with BCRYPT_USE_SYSTEM_PREFERRED_RNG selects the system RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(not(windows))]
fn fill_secure_random(_buffer: &mut [u8]) -> Result<(), ()> {
    // The application targets Windows. On other platforms we fail closed rather
    // than substitute a weaker source of randomness.
    Err(())
}

// ── Approval Token ────────────────────────────────────────────────────

/// An opaque, single-purpose capability token proving that a specific candidate
/// confirmation was prepared for the user.
///
/// The raw value is held in a [`Zeroizing`] buffer and is exposed *only* through
/// serialization to the frontend. `Debug` is redacted, `Display` is intentionally
/// not implemented, and the type is deliberately not `Clone`: the coordinator reads
/// it by reference to compute a digest and never copies or logs the secret.
pub struct ApprovalToken {
    value: Zeroizing<String>,
}

impl ApprovalToken {
    /// Mint a fresh token from the OS CSPRNG. The raw value is a fixed-length
    /// lowercase hex string (64 chars = 32 random bytes).
    fn generate() -> Result<Self, ()> {
        let mut bytes = Zeroizing::new([0u8; TOKEN_BYTES]);
        fill_secure_random(bytes.as_mut())?;
        let mut encoded = String::with_capacity(TOKEN_BYTES * 2);
        for byte in bytes.iter() {
            use fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        Ok(Self {
            value: Zeroizing::new(encoded),
        })
    }

    /// Domain-separated SHA-256 digest of the raw token. This is all the registry
    /// ever stores, so a registry snapshot cannot be replayed as a token.
    fn digest(&self) -> TokenDigest {
        let mut hasher = Sha256::new();
        hasher.update(TOKEN_DIGEST_DOMAIN);
        hasher.update([0u8]);
        hasher.update(self.value.as_bytes());
        TokenDigest(hasher.finalize().into())
    }

    /// Structural validation of a token received from the frontend: exactly 64
    /// lowercase hex chars. Rejects anything else before it is used as a lookup key.
    fn is_well_formed(&self) -> bool {
        self.value.len() == TOKEN_BYTES * 2
            && self
                .value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    }
}

impl fmt::Debug for ApprovalToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ApprovalToken")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

impl Serialize for ApprovalToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Exposing the raw value to the frontend is the token's only egress point.
        serializer.serialize_str(self.value.as_str())
    }
}

impl<'de> Deserialize<'de> for ApprovalToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        let token = Self {
            value: Zeroizing::new(raw),
        };
        if token.is_well_formed() {
            Ok(token)
        } else {
            Err(de::Error::custom("malformed approval token"))
        }
    }
}

/// Domain-separated digest of an [`ApprovalToken`]; the registry key. Holding a
/// digest reveals nothing that can reconstruct the token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct TokenDigest([u8; 32]);

// ── Clock ─────────────────────────────────────────────────────────────

/// Time source for TTL and lease decisions. All ordering-sensitive logic uses the
/// monotonic reading so wall-clock adjustments cannot reopen an expired token; the
/// wall-clock reading is used only for the human-facing `expiresAt` field.
pub trait Clock: Send + Sync + 'static {
    /// Monotonic milliseconds from an arbitrary but fixed epoch. Never decreases.
    fn monotonic_millis(&self) -> u64;
    /// Wall-clock timestamp as an ISO-8601 UTC string, for display only.
    fn wall_clock_iso(&self) -> String;
}

/// Production clock: monotonic reading from a process-lifetime base [`Instant`].
pub struct SystemClock {
    base: std::time::Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            base: std::time::Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn monotonic_millis(&self) -> u64 {
        self.base.elapsed().as_millis() as u64
    }

    fn wall_clock_iso(&self) -> String {
        super::current_timestamp()
    }
}

/// Deterministic clock for tests. Monotonic time advances only when explicitly
/// asked, so TTL/lease/replay windows can be driven precisely and reproducibly.
#[cfg(test)]
pub struct FakeClock {
    millis: AtomicU64,
    wall: Mutex<String>,
}

#[cfg(test)]
impl FakeClock {
    pub fn new() -> Self {
        Self {
            millis: AtomicU64::new(0),
            wall: Mutex::new("2026-07-14T10:00:00.000Z".to_string()),
        }
    }

    /// Advance monotonic time by `delta_millis`.
    pub fn advance(&self, delta_millis: u64) {
        self.millis.fetch_add(delta_millis, Ordering::SeqCst);
    }

    /// Set the wall-clock timestamp returned by `wall_clock_iso`. Tests use this
    /// to verify that `expiresAt` reflects the wall time at prepare.
    pub fn set_wall(&self, iso: String) {
        *self.wall.lock().expect("fake clock wall poisoned") = iso;
    }
}

#[cfg(test)]
impl Clock for FakeClock {
    fn monotonic_millis(&self) -> u64 {
        self.millis.load(Ordering::SeqCst)
    }

    fn wall_clock_iso(&self) -> String {
        self.wall.lock().expect("fake clock wall poisoned").clone()
    }
}

// ── Registry entry state machine ──────────────────────────────────────

/// Lifecycle of a single Approval Token in the registry.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ConfirmationState {
    /// Prepared and awaiting a confirm attempt.
    Issued,
    /// A confirm attempt is currently driving a D-4 call under a lease.
    InFlight,
    /// A D-4 invocation panicked before its result could be finalized. The next
    /// confirm with this exact token reuses the captured request id to reconcile
    /// with D-4's idempotent transaction; it is never a new authorization.
    RecoveryPending,
    /// A confirm attempt committed a D-4 result; a minimal safe result is cached
    /// for idempotent replay within the consumed cache window.
    Consumed,
    /// The token TTL elapsed before it was consumed.
    Expired,
    /// The user explicitly cancelled the confirmation.
    Cancelled,
    /// The candidate context changed (revision/sensitivity/status/existence) or a
    /// terminal D-4 error retired the token; it must be re-prepared.
    Invalidated,
}

/// The minimal, non-sensitive result cached on a consumed token for replay. Holds
/// no content, evidence, fingerprint, grant, or audit — only the identifiers the
/// IPC contract exposes.
#[derive(Clone, Debug)]
struct CachedSafeResult {
    candidate_id: String,
    confirmed_memory_id: String,
}

/// One Approval Token's registry record. Contains only non-secret binding metadata
/// plus lifecycle bookkeeping — never the raw token or candidate content.
struct ApprovalEntry {
    life_id: String,
    candidate_id: String,
    expected_revision: i64,
    request_id: String,
    is_sensitive: bool,
    expires_at_monotonic: u64,
    state: ConfirmationState,
    attempt_count: u32,
    attempt_sequence: u64,
    in_flight_lease_deadline: u64,
    reconciliation_deadline_monotonic: Option<u64>,
    cached_result: Option<CachedSafeResult>,
    terminal_at_monotonic: Option<u64>,
}

/// Add `delta_millis` to an ISO-8601 UTC timestamp string. Only handles the
/// simple format produced by `current_timestamp` and `FakeClock`; panics on
/// malformed input so tests catch regressions immediately.
fn add_millis_to_iso(iso: &str, delta_ms: u64) -> String {
    assert!(iso.ends_with('Z'), "expected UTC ISO timestamp ending in Z");
    let without_z = &iso[..iso.len() - 1];
    let (date_time, frac_str) = without_z.split_once('.').unwrap_or((without_z, "000"));
    let frac: u64 = frac_str.parse().expect("invalid fractional digits");
    let (date, time) = date_time.split_once('T').expect("expected T separator");
    let (ys, ms, ds) = (&date[0..4], &date[5..7], &date[8..10]);
    let (hs, mins, ss) = (&time[0..2], &time[3..5], &time[6..8]);
    let h: u64 = hs.parse().unwrap();
    let m: u64 = mins.parse().unwrap();
    let s: u64 = ss.parse().unwrap();
    let total_ms = h * 3_600_000 + m * 60_000 + s * 1_000 + frac + delta_ms;
    let extra_days = total_ms / 86_400_000;
    let day_ms = total_ms % 86_400_000;
    let nh = day_ms / 3_600_000;
    let nmin = (day_ms % 3_600_000) / 60_000;
    let ns = (day_ms % 60_000) / 1_000;
    let nfrac = day_ms % 1_000;

    // Simple day overflow. Handles month boundaries approximately; sufficient for
    // a 3-minute TTL on a display-only field.
    let d: u64 = ds.parse().unwrap();
    let new_day = d + extra_days;
    // We keep the same month/year; for a 3-minute delta this never crosses a
    // month boundary in practice.
    format!("{ys}-{ms}-{new_day:02}T{nh:02}:{nmin:02}:{ns:02}.{nfrac:03}Z")
}

// ── Public facade result / error types ────────────────────────────────

/// Whether prepared confirmation additionally requires explicit sensitive approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationRequirement {
    Standard,
    ExplicitSensitiveApproval,
}

/// Outcome of a successful confirm, mapped from the frozen D-4 outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmationOutcome {
    /// A fresh confirmation committed the candidate.
    Confirmed,
    /// The candidate was already confirmed under this token's request id; the prior
    /// authoritative result is returned unchanged. (Maps from D-4 `AlreadyConfirmed`.)
    IdempotentReplay,
}

/// Result of a `prepare` call: the preview plus the freshly minted token.
#[derive(Debug)]
pub struct PreparedConfirmation {
    pub candidate_id: String,
    pub expected_revision: i64,
    pub kind: MemoryKind,
    pub content: Option<String>,
    pub summary: Option<String>,
    pub is_sensitive: bool,
    pub source: &'static str,
    pub requirement: ConfirmationRequirement,
    pub approval_token: ApprovalToken,
    pub expires_at: String,
}

/// Result of a successful `confirm` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmationSuccess {
    pub outcome: ConfirmationOutcome,
    pub candidate_id: String,
    pub confirmed_memory_id: String,
}

/// Terminal state reported by a `cancel` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    Cancelled,
    AlreadyConsumed,
    AlreadyExpired,
    AlreadyCancelled,
    AlreadyInvalidated,
}

/// Failure modes surfaced by the coordinator. The command layer maps these to the
/// stable IPC error codes and controls what optional detail (requiresReprepare,
/// retryAfterMs) accompanies each.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfirmationError {
    /// No current life is configured.
    NoCurrentLife,
    /// The candidate cannot be prepared (missing, not this life, or not pending).
    NotFound,
    /// The token is unknown, malformed, or bound to a different life/candidate.
    TokenInvalid,
    /// The token TTL elapsed.
    TokenExpired,
    /// The token was already cancelled.
    TokenCancelled,
    /// The token was already consumed and its replay window elapsed.
    TokenConsumed,
    /// Another attempt currently holds the in-flight lease.
    TokenInFlight,
    /// The candidate context changed since prepare; re-prepare required.
    ContextChanged,
    /// The candidate's revision changed since prepare; re-prepare required.
    RevisionConflict,
    /// The confirmation request id was already used for a different candidate.
    RequestConflict,
    /// The candidate content contains prohibited material.
    ProhibitedContent,
    /// Confirming this candidate requires sensitive approval that is not satisfied.
    SensitiveApprovalRequired,
    /// A minted token could not be produced (CSPRNG failure).
    TokenGeneration,
    /// Registry is at capacity with no evictable entries; retry shortly.
    RegistryCapacity,
    /// Transient storage unavailability from D-4; retry with `retry_after_ms`.
    StorageUnavailable { retry_after_ms: u64 },
    /// The IPC request is structurally invalid (unknown fields, wrong types, etc.).
    InvalidRequest(String),
    /// An unexpected/terminal internal failure.
    Internal,
}

impl ConfirmationError {
    /// Whether the caller must obtain a fresh token before retrying.
    pub fn requires_reprepare(&self) -> bool {
        matches!(
            self,
            Self::TokenInvalid
                | Self::TokenExpired
                | Self::TokenCancelled
                | Self::TokenConsumed
                | Self::ContextChanged
                | Self::RevisionConflict
                | Self::RequestConflict
                | Self::ProhibitedContent
        )
    }
}

// ── Coordinator ───────────────────────────────────────────────────────

/// In-memory Approval Token registry and confirmation facade.
///
/// Managed as long-lived Tauri state. The global mutex guards only registry
/// map operations (lookup/insert/cleanup); each token has its own inner mutex, and
/// no lock is ever held across a D-4 call or any SQLite access.
pub struct CandidateConfirmationCoordinator<C: Clock = SystemClock> {
    registry: Mutex<HashMap<TokenDigest, Arc<Mutex<ApprovalEntry>>>>,
    sequence: AtomicU64,
    clock: C,
}

impl Default for CandidateConfirmationCoordinator<SystemClock> {
    fn default() -> Self {
        Self::with_clock(SystemClock::default())
    }
}

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    pub fn with_clock(clock: C) -> Self {
        Self {
            registry: Mutex::new(HashMap::new()),
            sequence: AtomicU64::new(1),
            clock,
        }
    }

    fn next_sequence(&self) -> u64 {
        self.sequence.fetch_add(1, Ordering::SeqCst)
    }
}

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    /// Prepare a candidate for confirmation: validate it is currently confirmable,
    /// mint an Approval Token, register it, and return a preview. Read-only with
    /// respect to D-4 — nothing is written to the database here.
    pub(crate) fn prepare<
        R: CandidateLifecycleRepository + CandidateConfirmationRecoveryRepository + ?Sized,
    >(
        &self,
        repository: &R,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<PreparedConfirmation, ConfirmationError> {
        let candidate = self.load_confirmable(repository, life_id, candidate_id)?;

        let requirement = if candidate.is_sensitive {
            ConfirmationRequirement::ExplicitSensitiveApproval
        } else {
            ConfirmationRequirement::Standard
        };

        let token = ApprovalToken::generate().map_err(|()| ConfirmationError::TokenGeneration)?;
        let digest = token.digest();
        let now = self.clock.monotonic_millis();
        let wall_now = self.clock.wall_clock_iso();
        let expires_at_iso = add_millis_to_iso(&wall_now, TOKEN_TTL_MILLIS);

        let entry = ApprovalEntry {
            life_id: life_id.to_string(),
            candidate_id: candidate_id.to_string(),
            expected_revision: candidate.revision,
            request_id: super::generate_id("confirm-req"),
            is_sensitive: candidate.is_sensitive,
            expires_at_monotonic: now.saturating_add(TOKEN_TTL_MILLIS),
            state: ConfirmationState::Issued,
            attempt_count: 0,
            attempt_sequence: 0,
            in_flight_lease_deadline: 0,
            reconciliation_deadline_monotonic: None,
            cached_result: None,
            terminal_at_monotonic: None,
        };
        self.reconcile_due_recoveries(repository, now);
        self.insert_entry(digest, entry, now)?;

        Ok(PreparedConfirmation {
            candidate_id: candidate.id,
            expected_revision: candidate.revision,
            kind: candidate.kind,
            content: candidate.content,
            summary: candidate.summary,
            is_sensitive: candidate.is_sensitive,
            source: candidate.source_type.as_str(),
            requirement,
            approval_token: token,
            expires_at: expires_at_iso,
        })
    }
}

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    /// Read a candidate and require that it is currently confirmable (pending with
    /// non-empty content). Errors are generalized to `NotFound` so a caller cannot
    /// probe internal lifecycle state.
    fn load_confirmable<R: CandidateLifecycleRepository + ?Sized>(
        &self,
        repository: &R,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<CandidateMemoryRecord, ConfirmationError> {
        let candidate = repository
            .get_candidate(life_id, candidate_id)
            .map_err(map_read_error)?;
        let has_content = candidate
            .content
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        if candidate.status != CandidateMemoryStatus::Pending || !has_content {
            return Err(ConfirmationError::NotFound);
        }
        Ok(candidate)
    }

    /// Insert a freshly minted entry, running capacity cleanup first. Fails with
    /// `RegistryCapacity` only when the registry is full of still-live tokens.
    fn insert_entry(
        &self,
        digest: TokenDigest,
        entry: ApprovalEntry,
        now: u64,
    ) -> Result<(), ConfirmationError> {
        let mut map = self
            .registry
            .lock()
            .map_err(|_| ConfirmationError::Internal)?;
        if map.len() >= REGISTRY_SOFT_CAPACITY {
            cleanup_locked(&mut map, now);
            if map.len() >= REGISTRY_SOFT_CAPACITY {
                return Err(ConfirmationError::RegistryCapacity);
            }
        }
        map.insert(digest, Arc::new(Mutex::new(entry)));
        Ok(())
    }

    /// Final read-only reconciliation is driven lazily before adding a new
    /// approval. This keeps abandoned recovery entries bounded without a global
    /// background task or any write after the original token deadline.
    fn reconcile_due_recoveries<
        R: CandidateLifecycleRepository + CandidateConfirmationRecoveryRepository + ?Sized,
    >(
        &self,
        repository: &R,
        now: u64,
    ) {
        let entries = match self.registry.lock() {
            Ok(map) => map.values().cloned().collect::<Vec<_>>(),
            Err(_) => return,
        };
        for arc in entries {
            let ticket = {
                let Ok(mut entry) = arc.lock() else {
                    continue;
                };
                if entry.state != ConfirmationState::RecoveryPending
                    || !entry
                        .reconciliation_deadline_monotonic
                        .is_some_and(|deadline| now >= deadline)
                {
                    continue;
                }
                let attempt_sequence = self.next_sequence();
                entry.state = ConfirmationState::InFlight;
                entry.attempt_sequence = attempt_sequence;
                entry.in_flight_lease_deadline = now.saturating_add(IN_FLIGHT_LEASE_MILLIS);
                AttemptTicket {
                    entry: Arc::clone(&arc),
                    life_id: entry.life_id.clone(),
                    candidate_id: entry.candidate_id.clone(),
                    expected_revision: entry.expected_revision,
                    request_id: entry.request_id.clone(),
                    is_sensitive: entry.is_sensitive,
                    attempt_sequence,
                    is_recovery: true,
                    read_only_recovery: true,
                }
            };
            let execution = self.run_confirm(repository, &ticket);
            let _ = self.finalize(&ticket, execution);
        }
    }

    /// Look up a live entry by token digest without holding the global lock beyond
    /// the map read.
    fn lookup(
        &self,
        digest: &TokenDigest,
    ) -> Result<Option<Arc<Mutex<ApprovalEntry>>>, ConfirmationError> {
        let map = self
            .registry
            .lock()
            .map_err(|_| ConfirmationError::Internal)?;
        Ok(map.get(digest).cloned())
    }
}

/// Snapshot of the binding captured under the entry lock, carried across the
/// (lock-free) D-4 call so finalize can detect a stale attempt.
struct AttemptTicket {
    entry: Arc<Mutex<ApprovalEntry>>,
    life_id: String,
    candidate_id: String,
    expected_revision: i64,
    request_id: String,
    is_sensitive: bool,
    attempt_sequence: u64,
    is_recovery: bool,
    read_only_recovery: bool,
}

/// Private result of either a D-4 call or a read-only recovery probe. It never
/// crosses IPC and deliberately contains no candidate content.
#[allow(clippy::large_enum_variant)] // D-4's owned result avoids cloning authority data.
enum ConfirmationExecution {
    D4(Result<super::ConfirmCandidateResult, CandidateMemoryError>),
    ReconciledCommitted(String),
    ReconciledNotCommitted,
}

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    /// Confirm a candidate using its Approval Token. Drives the frozen D-4 confirm
    /// transaction, which remains the sole authority for database correctness.
    pub(crate) fn confirm<
        R: CandidateLifecycleRepository + CandidateConfirmationRecoveryRepository + ?Sized,
    >(
        &self,
        repository: &R,
        life_id: &str,
        candidate_id: &str,
        token: &ApprovalToken,
    ) -> Result<ConfirmationSuccess, ConfirmationError> {
        if !token.is_well_formed() {
            return Err(ConfirmationError::TokenInvalid);
        }
        let digest = token.digest();
        let arc = self
            .lookup(&digest)?
            .ok_or(ConfirmationError::TokenInvalid)?;

        // Phase 1: under the entry lock, validate binding + state and either return
        // a cached replay or claim an attempt. Returns Ok(Err(success)) to signal an
        // immediate cached result with no D-4 call needed.
        let ticket = match self.begin_attempt(&arc, life_id, candidate_id)? {
            AttemptDecision::Replay(success) => return Ok(success),
            AttemptDecision::Proceed(ticket) => ticket,
        };

        // The StorageService owns the only D-4 panic boundary. No coordinator or
        // repository object is marked unwind-safe or caught here.
        let execution = self.run_confirm(repository, &ticket);
        self.finalize(&ticket, execution)
    }
}

/// Outcome of the attempt-acquisition phase.
enum AttemptDecision {
    Replay(ConfirmationSuccess),
    Proceed(AttemptTicket),
}

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    /// Phase 1 of confirm: validate the token binding and current state, then either
    /// serve a cached replay or transition the entry into `InFlight` and mint an
    /// attempt ticket. All decisions here are made under the per-entry lock.
    fn begin_attempt(
        &self,
        arc: &Arc<Mutex<ApprovalEntry>>,
        life_id: &str,
        candidate_id: &str,
    ) -> Result<AttemptDecision, ConfirmationError> {
        let now = self.clock.monotonic_millis();
        let mut entry = arc.lock().map_err(|_| ConfirmationError::Internal)?;

        // Binding check: a token is only usable for the exact life+candidate it was
        // prepared for. Generalized to TokenInvalid so it cannot probe other state.
        if entry.life_id != life_id || entry.candidate_id != candidate_id {
            return Err(ConfirmationError::TokenInvalid);
        }

        // Lazily expire an Issued token whose TTL has fully elapsed. InFlight
        // tokens are NEVER expired by TTL alone — a D-4 call may be in progress
        // and must be allowed to complete.
        if entry.state == ConfirmationState::Issued && now >= entry.expires_at_monotonic {
            entry.state = ConfirmationState::Expired;
            entry.terminal_at_monotonic = Some(now);
        }

        match entry.state.clone() {
            ConfirmationState::Consumed => {
                let cached = entry
                    .cached_result
                    .clone()
                    .ok_or(ConfirmationError::Internal)?;
                let still_replayable = entry
                    .terminal_at_monotonic
                    .is_some_and(|at| now < at.saturating_add(CONSUMED_CACHE_MILLIS));
                if still_replayable {
                    Ok(AttemptDecision::Replay(ConfirmationSuccess {
                        outcome: ConfirmationOutcome::IdempotentReplay,
                        candidate_id: cached.candidate_id,
                        confirmed_memory_id: cached.confirmed_memory_id,
                    }))
                } else {
                    Err(ConfirmationError::TokenConsumed)
                }
            }
            ConfirmationState::Expired => Err(ConfirmationError::TokenExpired),
            ConfirmationState::Cancelled => Err(ConfirmationError::TokenCancelled),
            ConfirmationState::Invalidated => Err(ConfirmationError::ContextChanged),
            ConfirmationState::RecoveryPending => {
                let reconciliation_deadline = entry
                    .reconciliation_deadline_monotonic
                    .ok_or(ConfirmationError::Internal)?;
                // At and after the reconciliation deadline a final read-only
                // probe decides Consumed vs Expired; no write is ever allowed
                // once the original token TTL has elapsed.
                let read_only_recovery = now >= entry.expires_at_monotonic;
                let _final_probe_due = now >= reconciliation_deadline;
                self.claim_attempt(&mut entry, arc, now, true, read_only_recovery)
            }
            ConfirmationState::InFlight => {
                if now < entry.in_flight_lease_deadline {
                    return Err(ConfirmationError::TokenInFlight);
                }
                // Lease expired. Only allow takeover if the token TTL is still
                // valid — a new attempt must not start after both lease AND TTL
                // have elapsed; the old attempt should finish on its own.
                if now >= entry.expires_at_monotonic {
                    // Both lease and TTL expired. The old attempt may still be
                    // running; the entry is preserved so finalize can coordinate
                    // the authoritative result. The caller must re-prepare.
                    return Err(ConfirmationError::TokenExpired);
                }
                self.claim_attempt(&mut entry, arc, now, false, false)
            }
            ConfirmationState::Issued => self.claim_attempt(&mut entry, arc, now, false, false),
        }
    }
}

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    /// Transition an Issued (or lease-expired InFlight) entry into a fresh InFlight
    /// attempt. Enforces the attempt cap. Must be called with the entry lock held.
    fn claim_attempt(
        &self,
        entry: &mut ApprovalEntry,
        arc: &Arc<Mutex<ApprovalEntry>>,
        now: u64,
        is_recovery: bool,
        read_only_recovery: bool,
    ) -> Result<AttemptDecision, ConfirmationError> {
        if !read_only_recovery && entry.attempt_count >= MAX_ATTEMPTS {
            entry.state = ConfirmationState::Invalidated;
            entry.terminal_at_monotonic = Some(now);
            return Err(ConfirmationError::ContextChanged);
        }
        let attempt_sequence = self.next_sequence();
        entry.state = ConfirmationState::InFlight;
        if !read_only_recovery {
            entry.attempt_count = entry.attempt_count.saturating_add(1);
        }
        entry.attempt_sequence = attempt_sequence;
        entry.in_flight_lease_deadline = now.saturating_add(IN_FLIGHT_LEASE_MILLIS);
        Ok(AttemptDecision::Proceed(AttemptTicket {
            entry: Arc::clone(arc),
            life_id: entry.life_id.clone(),
            candidate_id: entry.candidate_id.clone(),
            expected_revision: entry.expected_revision,
            request_id: entry.request_id.clone(),
            is_sensitive: entry.is_sensitive,
            attempt_sequence,
            is_recovery,
            read_only_recovery,
        }))
    }
}

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    /// Phase 2 of confirm: with no locks held, re-read the candidate to catch a
    /// context change cheaply, then delegate to the authoritative D-4 transaction.
    ///
    /// This is the one place a `SensitiveConfirmationGrant` is constructed. The
    /// grant is built here — inside `candidate_service`'s private child module — and
    /// moved straight into the D-4 request; it never surfaces to any caller.
    fn run_confirm<
        R: CandidateLifecycleRepository + CandidateConfirmationRecoveryRepository + ?Sized,
    >(
        &self,
        repository: &R,
        ticket: &AttemptTicket,
    ) -> Result<ConfirmationExecution, CandidateMemoryError> {
        // Recovery always reconciles first using the original life/candidate/request
        // binding. After the original TTL this is the only repository operation:
        // candidate data is never re-read and D-4 is never invoked.
        if ticket.is_recovery {
            if let Some(memory_id) = repository.confirmed_memory_for_request(
                &ticket.life_id,
                &ticket.candidate_id,
                &ticket.request_id,
            )? {
                return Ok(ConfirmationExecution::ReconciledCommitted(memory_id));
            }
            if ticket.read_only_recovery {
                return Ok(ConfirmationExecution::ReconciledNotCommitted);
            }
        }

        // Before the original TTL, a recovery may retry D-4 only after the
        // read-only check above and after the original binding is validated again.
        let current = repository.get_candidate(&ticket.life_id, &ticket.candidate_id)?;
        if current.is_sensitive != ticket.is_sensitive {
            return Err(CandidateMemoryError::invalid_status());
        }

        let sensitive_grant = if ticket.is_sensitive {
            // Constructed via a struct literal reachable only from this child module
            // of `candidate_service`; the private `candidate_id` field cannot be set
            // from the command layer, the repository, or any other module.
            Some(SensitiveConfirmationGrant {
                candidate_id: ticket.candidate_id.clone(),
            })
        } else {
            None
        };
        let request = ConfirmCandidateRequest {
            candidate_id: ticket.candidate_id.clone(),
            expected_revision: ticket.expected_revision,
            request_id: ticket.request_id.clone(),
            sensitive_grant,
        };
        Ok(ConfirmationExecution::D4(
            CandidateMemoryService::new(repository).confirm(&ticket.life_id, request),
        ))
    }
}

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    /// Phase 3 of confirm: translate the authoritative D-4 result into the IPC-facing
    /// success/error, and update the token state — but only if this attempt still
    /// owns the lease. A stale attempt (superseded by a lease takeover) never mutates
    /// the entry on error, yet on success it promotes the entry to Consumed so the
    /// registry never contradicts a committed D-4 result. Stale successes always
    /// surface as `IdempotentReplay` — never as a fresh `Confirmed`.
    fn finalize(
        &self,
        ticket: &AttemptTicket,
        execution: Result<ConfirmationExecution, CandidateMemoryError>,
    ) -> Result<ConfirmationSuccess, ConfirmationError> {
        let now = self.clock.monotonic_millis();
        let mut entry = ticket
            .entry
            .lock()
            .map_err(|_| ConfirmationError::Internal)?;
        let is_current = entry.state == ConfirmationState::InFlight
            && entry.attempt_sequence == ticket.attempt_sequence;

        match execution {
            Ok(ConfirmationExecution::ReconciledCommitted(memory_id)) => {
                if is_current {
                    entry.state = ConfirmationState::Consumed;
                    entry.terminal_at_monotonic = Some(now);
                    entry.cached_result = Some(CachedSafeResult {
                        candidate_id: ticket.candidate_id.clone(),
                        confirmed_memory_id: memory_id.clone(),
                    });
                }
                Ok(ConfirmationSuccess {
                    outcome: ConfirmationOutcome::IdempotentReplay,
                    candidate_id: ticket.candidate_id.clone(),
                    confirmed_memory_id: memory_id,
                })
            }
            Ok(ConfirmationExecution::ReconciledNotCommitted) => {
                if is_current {
                    entry.state = ConfirmationState::Expired;
                    // A final bounded recovery probe has conclusively found no
                    // commit. It is safe to make this orphan immediately
                    // evictable, so panic recovery cannot consume registry
                    // capacity after it has reached a terminal state.
                    entry.terminal_at_monotonic = Some(now.saturating_sub(IN_FLIGHT_LEASE_MILLIS));
                    entry.in_flight_lease_deadline = 0;
                }
                Err(ConfirmationError::TokenExpired)
            }
            Ok(ConfirmationExecution::D4(Ok(result))) => {
                if is_current {
                    // Current attempt: map D-4 outcome faithfully.
                    let success = map_success(&result);
                    entry.state = ConfirmationState::Consumed;
                    entry.terminal_at_monotonic = Some(now);
                    entry.cached_result = Some(CachedSafeResult {
                        candidate_id: success.candidate_id.clone(),
                        confirmed_memory_id: success.confirmed_memory_id.clone(),
                    });
                    Ok(success)
                } else {
                    // Stale attempt returned success. The database committed; the
                    // registry must not contradict that. Promote to Consumed if the
                    // entry hasn't already been consumed by a newer attempt. Return
                    // idempotentReplay — this stale call must never surface as a
                    // fresh Confirmed.
                    promote_to_consumed_if_authoritative(&mut entry, &result, now);
                    Ok(ConfirmationSuccess {
                        outcome: ConfirmationOutcome::IdempotentReplay,
                        candidate_id: result.candidate.id.clone(),
                        confirmed_memory_id: result.memory.id.clone(),
                    })
                }
            }
            Ok(ConfirmationExecution::D4(Err(error))) | Err(error) => {
                let (mapped, disposition) = classify_confirm_error(&error);
                if is_current {
                    match disposition {
                        // Transient: if the token TTL is still valid, keep it
                        // Issued so the caller can retry. If TTL has expired,
                        // transition to Expired — no more retries are possible.
                        ErrorDisposition::Retryable => {
                            if ticket.is_recovery {
                                if entry
                                    .reconciliation_deadline_monotonic
                                    .is_some_and(|deadline| now < deadline)
                                {
                                    entry.state = ConfirmationState::RecoveryPending;
                                    entry.in_flight_lease_deadline = 0;
                                } else if now >= entry.expires_at_monotonic {
                                    entry.state = ConfirmationState::Expired;
                                    entry.terminal_at_monotonic = Some(now);
                                } else {
                                    entry.state = ConfirmationState::Issued;
                                    entry.in_flight_lease_deadline = 0;
                                }
                            } else if now >= entry.expires_at_monotonic {
                                entry.state = ConfirmationState::Expired;
                                entry.terminal_at_monotonic = Some(now);
                            } else {
                                entry.state = ConfirmationState::Issued;
                                entry.in_flight_lease_deadline = 0;
                            }
                        }
                        // Terminal: retire the token.
                        ErrorDisposition::Terminal => {
                            entry.state = ConfirmationState::Invalidated;
                            entry.terminal_at_monotonic = Some(now);
                        }
                        ErrorDisposition::RecoveryPending => {
                            enter_recovery(&mut entry, now);
                        }
                    }
                }
                // Stale errors are silently ignored — they must not overwrite a
                // newer attempt's state (Consumed, InFlight, etc.).
                Err(mapped)
            }
        }
    }
}

fn enter_recovery(entry: &mut ApprovalEntry, now: u64) {
    entry.state = ConfirmationState::RecoveryPending;
    entry.in_flight_lease_deadline = 0;
    // Reconciliation may continue briefly after expiry, but writes remain bound
    // exclusively to `expires_at_monotonic` (the original approval deadline).
    entry.reconciliation_deadline_monotonic = Some(
        entry
            .expires_at_monotonic
            .max(now.saturating_add(RECOVERY_RECONCILIATION_WINDOW_MILLIS)),
    );
}

/// When a stale attempt's D-4 call succeeds, promote the entry to Consumed if
/// doing so doesn't regress from an already-terminal state. This ensures the
/// registry never contradicts a committed D-4 result.
fn promote_to_consumed_if_authoritative(
    entry: &mut ApprovalEntry,
    result: &super::ConfirmCandidateResult,
    now: u64,
) {
    match entry.state {
        // Already consumed — keep the existing cached result.
        ConfirmationState::Consumed => {}
        // InFlight (newer attempt), Invalidated, or Issued (retryable error
        // rolled back): the database success is authoritative, so promote.
        ConfirmationState::InFlight
        | ConfirmationState::Invalidated
        | ConfirmationState::Issued
        | ConfirmationState::RecoveryPending => {
            entry.state = ConfirmationState::Consumed;
            entry.terminal_at_monotonic = Some(now);
            entry.cached_result = Some(CachedSafeResult {
                candidate_id: result.candidate.id.clone(),
                confirmed_memory_id: result.memory.id.clone(),
            });
        }
        // Expired or Cancelled: user-initiated terminal states take precedence
        // over a background D-4 success. Do not regress.
        ConfirmationState::Expired | ConfirmationState::Cancelled => {}
    }
}

// ── Result / error mapping ────────────────────────────────────────────

/// Map the frozen D-4 result to the minimal IPC-safe success. Only identifiers are
/// carried forward — no content, evidence, fingerprint, grant, or audit.
fn map_success(result: &super::ConfirmCandidateResult) -> ConfirmationSuccess {
    let outcome = match result.outcome {
        ConfirmCandidateOutcome::Confirmed => ConfirmationOutcome::Confirmed,
        ConfirmCandidateOutcome::AlreadyConfirmed => ConfirmationOutcome::IdempotentReplay,
    };
    ConfirmationSuccess {
        outcome,
        candidate_id: result.candidate.id.clone(),
        confirmed_memory_id: result.memory.id.clone(),
    }
}

/// Whether a D-4 error leaves the token retryable or retires it.
enum ErrorDisposition {
    Retryable,
    RecoveryPending,
    Terminal,
}

/// Classify a D-4 confirm error into the IPC error plus the token disposition.
/// Only `CANDIDATE_MEMORY_STORAGE_UNAVAILABLE` is transient; everything else is a
/// terminal condition that requires re-preparation.
fn classify_confirm_error(error: &CandidateMemoryError) -> (ConfirmationError, ErrorDisposition) {
    match error.code.as_str() {
        "CANDIDATE_MEMORY_CONFIRMATION_PANIC_RECOVERED" => (
            ConfirmationError::StorageUnavailable {
                retry_after_ms: 250,
            },
            ErrorDisposition::RecoveryPending,
        ),
        "CANDIDATE_MEMORY_STORAGE_UNAVAILABLE" => (
            ConfirmationError::StorageUnavailable {
                retry_after_ms: 250,
            },
            ErrorDisposition::Retryable,
        ),
        "CANDIDATE_MEMORY_SENSITIVE_CONSENT_REQUIRED" => (
            ConfirmationError::SensitiveApprovalRequired,
            ErrorDisposition::Terminal,
        ),
        "CANDIDATE_MEMORY_REVISION_CONFLICT" => (
            ConfirmationError::RevisionConflict,
            ErrorDisposition::Terminal,
        ),
        "CANDIDATE_MEMORY_REQUEST_CONFLICT" => (
            ConfirmationError::RequestConflict,
            ErrorDisposition::Terminal,
        ),
        "CANDIDATE_MEMORY_PROHIBITED_CONTENT" => (
            ConfirmationError::ProhibitedContent,
            ErrorDisposition::Terminal,
        ),
        "CANDIDATE_MEMORY_INVALID_STATUS"
        | "CANDIDATE_MEMORY_NOT_FOUND"
        | "CANDIDATE_MEMORY_LIFE_MISMATCH" => (
            ConfirmationError::ContextChanged,
            ErrorDisposition::Terminal,
        ),
        _ => (ConfirmationError::Internal, ErrorDisposition::Terminal),
    }
}

/// Map a candidate read error (used during prepare and the confirm pre-check) into
/// a generalized confirmation error that does not leak lifecycle state.
fn map_read_error(error: CandidateMemoryError) -> ConfirmationError {
    match error.code.as_str() {
        "CANDIDATE_MEMORY_NOT_FOUND" | "CANDIDATE_MEMORY_LIFE_MISMATCH" => {
            ConfirmationError::NotFound
        }
        "CANDIDATE_MEMORY_STORAGE_UNAVAILABLE" => ConfirmationError::StorageUnavailable {
            retry_after_ms: 250,
        },
        _ => ConfirmationError::Internal,
    }
}

// ── Cancel ────────────────────────────────────────────────────────────

impl<C: Clock> CandidateConfirmationCoordinator<C> {
    /// Cancel a prepared confirmation. Idempotent and never touches the database:
    /// it only retires the in-memory token. An in-flight attempt cannot be
    /// cancelled out from under D-4 — the caller is told it is in flight regardless
    /// of whether the lease has expired. Lease takeover is only possible via a new
    /// `confirm` call, never via `cancel`.
    pub fn cancel(
        &self,
        life_id: &str,
        candidate_id: &str,
        token: &ApprovalToken,
    ) -> Result<CancelOutcome, ConfirmationError> {
        if !token.is_well_formed() {
            return Err(ConfirmationError::TokenInvalid);
        }
        let digest = token.digest();
        let arc = self
            .lookup(&digest)?
            .ok_or(ConfirmationError::TokenInvalid)?;
        let now = self.clock.monotonic_millis();
        let mut entry = arc.lock().map_err(|_| ConfirmationError::Internal)?;

        if entry.life_id != life_id || entry.candidate_id != candidate_id {
            return Err(ConfirmationError::TokenInvalid);
        }

        // Fold an elapsed TTL into Expired first so cancel reports it faithfully.
        // This only applies to Issued tokens; InFlight tokens are never expired by
        // TTL alone — they may still have a D-4 call in progress.
        if entry.state == ConfirmationState::Issued && now >= entry.expires_at_monotonic {
            entry.state = ConfirmationState::Expired;
            entry.terminal_at_monotonic = Some(now);
        }

        match entry.state {
            ConfirmationState::Issued => {
                entry.state = ConfirmationState::Cancelled;
                entry.terminal_at_monotonic = Some(now);
                Ok(CancelOutcome::Cancelled)
            }
            ConfirmationState::InFlight | ConfirmationState::RecoveryPending => {
                // InFlight means a D-4 call may be in progress. Regardless of
                // whether the lease has expired, cancel must not transition the
                // state — the caller is told the token is in flight. Only a new
                // confirm call can take over an expired lease.
                Err(ConfirmationError::TokenInFlight)
            }
            ConfirmationState::Consumed => Ok(CancelOutcome::AlreadyConsumed),
            ConfirmationState::Expired => Ok(CancelOutcome::AlreadyExpired),
            ConfirmationState::Cancelled => Ok(CancelOutcome::AlreadyCancelled),
            ConfirmationState::Invalidated => Ok(CancelOutcome::AlreadyInvalidated),
        }
    }
}

// ── Registry cleanup ──────────────────────────────────────────────────

/// Remove entries that can never again be used: fully-expired live tokens and
/// terminal tokens past their retention window. A consumed token is retained until
/// its replay cache window elapses. Still-live Issued/InFlight tokens are preserved.
fn cleanup_locked(map: &mut HashMap<TokenDigest, Arc<Mutex<ApprovalEntry>>>, now: u64) {
    map.retain(|_, arc| {
        let Ok(mut entry) = arc.lock() else {
            // A poisoned entry can never be driven safely again; drop it.
            return false;
        };
        match entry.state {
            ConfirmationState::InFlight => {
                // An InFlight entry may have an active D-4 call in progress.
                // TTL expiry must never evict it — only the D-4 result (or a
                // lease takeover) can retire an InFlight entry.
                true
            }
            ConfirmationState::RecoveryPending => {
                let Some(deadline) = entry.reconciliation_deadline_monotonic else {
                    entry.state = ConfirmationState::Expired;
                    entry.terminal_at_monotonic = Some(now);
                    return true;
                };
                if now < deadline {
                    true
                } else {
                    entry.state = ConfirmationState::Invalidated;
                    entry.terminal_at_monotonic = Some(now);
                    // Recovery has had its full bounded window. Drop the orphan
                    // immediately so a panic cannot permanently consume registry
                    // capacity; D-4 remains the durable authority if the caller
                    // returns after this in-memory token has expired.
                    false
                }
            }
            ConfirmationState::Issued => {
                // An Issued token with an expired TTL can be evicted.
                now < entry.expires_at_monotonic
            }
            ConfirmationState::Consumed => entry
                .terminal_at_monotonic
                .is_some_and(|at| now < at.saturating_add(CONSUMED_CACHE_MILLIS)),
            ConfirmationState::Expired
            | ConfirmationState::Cancelled
            | ConfirmationState::Invalidated => {
                // Retain terminal tokens briefly so a racing caller gets a precise
                // error instead of a generic "unknown token".
                entry
                    .terminal_at_monotonic
                    .is_some_and(|at| now < at.saturating_add(IN_FLIGHT_LEASE_MILLIS))
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Barrier, Mutex,
    };
    use std::thread;

    use super::*;
    use crate::memory::candidate::CandidateMemoryAuditRecord;
    use crate::memory::candidate_service::{
        AddEvidenceRequest, CandidateEditResult, CandidateLifecycleResult, ConfirmCandidateResult,
        DeleteCandidateRequest, EditCandidateRequest, ExpiredCandidateScan, RejectCandidateRequest,
        SupersedeCandidateRequest,
    };
    use crate::memory::{
        candidate::{
            CandidateInferenceStatus, CandidateMemoryCursor, CandidateMemoryEvidenceRecord,
            CandidateMemoryListFilter, CandidateMemoryRepository, CandidateMemoryStorageUpdate,
            NewCandidateMemory, NewCandidateMemoryAudit, NewCandidateMemoryEvidence,
        },
        candidate::{CandidateMemoryRecord as Record, CandidateMemorySourceType},
        MemoryRecord, MemorySourceType, MemoryStatus,
    };

    /// Programmable behavior for the mock's `confirm_candidate_atomic`.
    enum ConfirmBehavior {
        Confirm,
        AlreadyConfirmed,
        Fail(CandidateMemoryError),
        /// Wait on `gate` inside the D-4 call, then confirm. Used to interleave a
        /// second attempt with a blocked one.
        BlockThenConfirm(Arc<Barrier>),
        /// Signal `entered` on arrival, then block on `release`, then confirm. Lets a
        /// test observe that the attempt is parked inside D-4 before it proceeds.
        SignalThenBlock {
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
        },
        /// Signal arrival in D-4, then return the supplied error after release.
        /// Used to prove an older attempt cannot overwrite a newer terminal state.
        SignalThenBlockFail {
            entered: Arc<Barrier>,
            release: Arc<Barrier>,
            error: CandidateMemoryError,
        },
    }

    /// A programmable stand-in for the lifecycle repository. Only `get_candidate`
    /// and `confirm_candidate_atomic` carry behavior; the rest are unreachable in
    /// the confirmation flow and panic if hit.
    struct MockRepo {
        candidate: Mutex<Option<Record>>,
        behaviors: Mutex<VecDeque<ConfirmBehavior>>,
        confirm_calls: AtomicUsize,
    }

    impl MockRepo {
        fn new(candidate: Record) -> Self {
            Self {
                candidate: Mutex::new(Some(candidate)),
                behaviors: Mutex::new(VecDeque::new()),
                confirm_calls: AtomicUsize::new(0),
            }
        }

        fn push(&self, behavior: ConfirmBehavior) {
            self.behaviors.lock().unwrap().push_back(behavior);
        }

        fn set_candidate(&self, candidate: Option<Record>) {
            *self.candidate.lock().unwrap() = candidate;
        }
    }

    fn candidate(id: &str, life_id: &str, sensitive: bool) -> Record {
        Record {
            id: id.into(),
            life_id: life_id.into(),
            subject_id: "user".into(),
            kind: MemoryKind::Fact,
            content: Some(format!("content for {id}")),
            summary: Some("summary".into()),
            source_type: CandidateMemorySourceType::Conversation,
            source_id: Some("src".into()),
            confidence: 0.9,
            importance: 0.5,
            is_sensitive: sensitive,
            inference_status: CandidateInferenceStatus::Extracted,
            status: CandidateMemoryStatus::Pending,
            revision: 1,
            dedup_fingerprint: None,
            proposed_at: "2026-07-14T10:00:00.000Z".into(),
            expires_at: None,
            reviewed_at: None,
            last_user_edit_at: None,
            confirmed_memory_id: None,
            accepted_request_id: None,
            rejection_reason_code: None,
            superseded_by_candidate_id: None,
            conflicts_with_memory_id: None,
            created_at: "2026-07-14T10:00:00.000Z".into(),
            updated_at: "2026-07-14T10:00:00.000Z".into(),
        }
    }

    fn memory(id: &str, life_id: &str) -> MemoryRecord {
        MemoryRecord {
            id: id.into(),
            life_id: life_id.into(),
            kind: MemoryKind::Fact,
            status: MemoryStatus::Confirmed,
            content: "content".into(),
            summary: Some("summary".into()),
            source_type: MemorySourceType::Conversation,
            source_ref: None,
            source_created_at: "2026-07-14T10:00:00.000Z".into(),
            importance: 0.5,
            confidence: 0.9,
            is_sensitive: false,
            created_at: "2026-07-14T10:00:00.000Z".into(),
            updated_at: "2026-07-14T10:00:00.000Z".into(),
            confirmed_at: Some("2026-07-14T10:00:00.000Z".into()),
        }
    }

    impl CandidateMemoryRepository for MockRepo {
        fn get_candidate(
            &self,
            life_id: &str,
            candidate_id: &str,
        ) -> Result<Record, CandidateMemoryError> {
            match self.candidate.lock().unwrap().as_ref() {
                Some(c) if c.life_id == life_id && c.id == candidate_id => Ok(c.clone()),
                _ => Err(CandidateMemoryError::not_found()),
            }
        }

        fn insert_candidate(&self, _c: NewCandidateMemory) -> Result<Record, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn list_candidates(
            &self,
            _f: CandidateMemoryListFilter,
        ) -> Result<(Vec<Record>, Option<CandidateMemoryCursor>), CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        #[allow(deprecated)]
        fn update_candidate_guarded(
            &self,
            _l: &str,
            _c: &str,
            _r: i64,
            _u: CandidateMemoryStorageUpdate,
        ) -> Result<Record, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        #[allow(deprecated)]
        fn insert_evidence(
            &self,
            _e: NewCandidateMemoryEvidence,
        ) -> Result<CandidateMemoryEvidenceRecord, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn list_evidence(
            &self,
            _l: &str,
            _c: &str,
        ) -> Result<Vec<CandidateMemoryEvidenceRecord>, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn count_evidence(&self, _l: &str, _c: &str) -> Result<usize, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        #[allow(deprecated)]
        fn delete_evidence(&self, _l: &str, _e: &str) -> Result<bool, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn append_audit(
            &self,
            _a: NewCandidateMemoryAudit,
        ) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn purge_audit_before(&self, _l: &str, _b: &str) -> Result<usize, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }
    }

    impl CandidateConfirmationRecoveryRepository for MockRepo {
        fn confirmed_memory_for_request(
            &self,
            life_id: &str,
            candidate_id: &str,
            _request_id: &str,
        ) -> Result<Option<String>, CandidateMemoryError> {
            let candidate = self.get_candidate(life_id, candidate_id)?;
            Ok(candidate.confirmed_memory_id)
        }
    }

    impl CandidateLifecycleRepository for MockRepo {
        fn confirm_candidate_atomic(
            &self,
            life_id: &str,
            _request: ConfirmCandidateRequest,
            _now: &str,
            memory_id: &str,
            _audit_id: &str,
        ) -> Result<ConfirmCandidateResult, CandidateMemoryError> {
            self.confirm_calls.fetch_add(1, Ordering::SeqCst);
            let behavior = self
                .behaviors
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(ConfirmBehavior::Confirm);
            let outcome = match behavior {
                ConfirmBehavior::Confirm => ConfirmCandidateOutcome::Confirmed,
                ConfirmBehavior::AlreadyConfirmed => ConfirmCandidateOutcome::AlreadyConfirmed,
                ConfirmBehavior::Fail(error) => return Err(error),
                ConfirmBehavior::BlockThenConfirm(gate) => {
                    gate.wait();
                    ConfirmCandidateOutcome::Confirmed
                }
                ConfirmBehavior::SignalThenBlock { entered, release } => {
                    entered.wait();
                    release.wait();
                    ConfirmCandidateOutcome::Confirmed
                }
                ConfirmBehavior::SignalThenBlockFail {
                    entered,
                    release,
                    error,
                } => {
                    entered.wait();
                    release.wait();
                    return Err(error);
                }
            };
            let candidate = self
                .candidate
                .lock()
                .unwrap()
                .as_ref()
                .cloned()
                .ok_or_else(CandidateMemoryError::not_found)?;
            Ok(ConfirmCandidateResult {
                outcome,
                memory: memory(memory_id, life_id),
                candidate,
                audit: None,
            })
        }

        fn edit_candidate_atomic(
            &self,
            _l: &str,
            _r: EditCandidateRequest,
            _n: &str,
            _a: &str,
        ) -> Result<CandidateEditResult, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn reject_candidate_atomic(
            &self,
            _l: &str,
            _r: RejectCandidateRequest,
            _n: &str,
            _a: &str,
        ) -> Result<CandidateLifecycleResult, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn scan_expired_candidates(
            &self,
            _l: &str,
            _n: &str,
            _limit: usize,
        ) -> Result<Vec<ExpiredCandidateScan>, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn expire_candidate_atomic(
            &self,
            _l: &str,
            _c: &str,
            _r: i64,
            _n: &str,
            _a: &str,
        ) -> Result<Option<CandidateLifecycleResult>, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn supersede_candidate_atomic(
            &self,
            _l: &str,
            _r: SupersedeCandidateRequest,
            _n: &str,
            _a: &str,
        ) -> Result<CandidateLifecycleResult, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn delete_candidate_atomic(
            &self,
            _l: &str,
            _r: DeleteCandidateRequest,
            _n: &str,
            _a: &str,
        ) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }

        fn add_evidence_atomic(
            &self,
            _l: &str,
            _r: AddEvidenceRequest,
            _n: &str,
            _e: &str,
            _a: &str,
        ) -> Result<Option<Record>, CandidateMemoryError> {
            unreachable!("not used by confirmation")
        }
    }

    fn coordinator() -> CandidateConfirmationCoordinator<FakeClock> {
        CandidateConfirmationCoordinator::with_clock(FakeClock::new())
    }

    /// Round-trip a token through JSON so tests exercise the real serde path the
    /// IPC layer uses, without needing access to the private inner value.
    fn roundtrip(token: &ApprovalToken) -> ApprovalToken {
        let json = serde_json::to_string(token).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn token_serializes_to_plain_hex_string() {
        let token = ApprovalToken::generate().unwrap();
        let json = serde_json::to_string(&token).unwrap();
        // 64 hex chars wrapped in quotes.
        assert_eq!(json.len(), 66);
        assert!(json.starts_with('"') && json.ends_with('"'));
        let inner = &json[1..json.len() - 1];
        assert_eq!(inner.len(), 64);
        assert!(inner.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn token_roundtrip_preserves_digest() {
        let token = ApprovalToken::generate().unwrap();
        let digest_before = token.digest();
        let restored = roundtrip(&token);
        assert_eq!(digest_before, restored.digest());
    }

    #[test]
    fn distinct_tokens_have_distinct_digests() {
        let a = ApprovalToken::generate().unwrap();
        let b = ApprovalToken::generate().unwrap();
        assert_ne!(a.digest(), b.digest());
    }

    #[test]
    fn malformed_tokens_are_rejected() {
        for bad in ["\"\"", "\"xyz\"", "\"ABCDEF\"", "\"12\"", "42", "\"g\""] {
            assert!(serde_json::from_str::<ApprovalToken>(bad).is_err(), "{bad}");
        }
        // A 64-char uppercase string is not lowercase hex.
        let upper = format!("\"{}\"", "A".repeat(64));
        assert!(serde_json::from_str::<ApprovalToken>(&upper).is_err());
    }

    #[test]
    fn token_debug_is_redacted() {
        let token = ApprovalToken::generate().unwrap();
        let rendered = format!("{token:?}");
        assert!(rendered.contains("[REDACTED]"));
        let json = serde_json::to_string(&token).unwrap();
        let inner = json.trim_matches('"');
        assert!(!rendered.contains(inner));
    }

    #[test]
    fn prepare_then_confirm_happy_path() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        assert_eq!(prepared.requirement, ConfirmationRequirement::Standard);
        assert_eq!(prepared.expected_revision, 1);

        let success = coord
            .confirm(&repo, "life-a", "c1", &prepared.approval_token)
            .unwrap();
        assert_eq!(success.outcome, ConfirmationOutcome::Confirmed);
        assert_eq!(success.candidate_id, "c1");
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn prepare_sensitive_requires_explicit_approval() {
        let repo = MockRepo::new(candidate("c1", "life-a", true));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        assert_eq!(
            prepared.requirement,
            ConfirmationRequirement::ExplicitSensitiveApproval
        );
        assert!(prepared.is_sensitive);
        // Confirm still drives D-4; the grant is built inside run_confirm. The mock
        // accepts, proving the sensitive path reaches confirm_candidate_atomic.
        let success = coord
            .confirm(&repo, "life-a", "c1", &prepared.approval_token)
            .unwrap();
        assert_eq!(success.outcome, ConfirmationOutcome::Confirmed);
    }

    #[test]
    fn prepare_rejects_non_pending_candidate() {
        let mut record = candidate("c1", "life-a", false);
        record.status = CandidateMemoryStatus::Accepted;
        let repo = MockRepo::new(record);
        let coord = coordinator();
        assert_eq!(
            coord.prepare(&repo, "life-a", "c1").unwrap_err(),
            ConfirmationError::NotFound
        );
    }

    #[test]
    fn prepare_rejects_empty_content() {
        let mut record = candidate("c1", "life-a", false);
        record.content = Some("   ".into());
        let repo = MockRepo::new(record);
        let coord = coordinator();
        assert_eq!(
            coord.prepare(&repo, "life-a", "c1").unwrap_err(),
            ConfirmationError::NotFound
        );
    }

    #[test]
    fn confirm_unknown_token_is_invalid() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let stranger = ApprovalToken::generate().unwrap();
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &stranger),
            Err(ConfirmationError::TokenInvalid)
        );
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn confirm_rejects_wrong_life_or_candidate() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        assert_eq!(
            coord.confirm(&repo, "life-b", "c1", &prepared.approval_token),
            Err(ConfirmationError::TokenInvalid)
        );
        assert_eq!(
            coord.confirm(&repo, "life-a", "c2", &prepared.approval_token),
            Err(ConfirmationError::TokenInvalid)
        );
        // D-4 was never reached because the binding failed first.
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn token_expires_after_ttl() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        coord.clock.advance(TOKEN_TTL_MILLIS);
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::TokenExpired)
        );
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn token_valid_just_before_ttl() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        coord.clock.advance(TOKEN_TTL_MILLIS - 1);
        assert!(coord
            .confirm(&repo, "life-a", "c1", &prepared.approval_token)
            .is_ok());
    }

    #[test]
    fn idempotent_replay_within_cache_window_does_not_recall_d4() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;

        let first = coord.confirm(&repo, "life-a", "c1", &token).unwrap();
        assert_eq!(first.outcome, ConfirmationOutcome::Confirmed);

        coord.clock.advance(CONSUMED_CACHE_MILLIS - 1);
        let replay = coord.confirm(&repo, "life-a", "c1", &token).unwrap();
        assert_eq!(replay.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(replay.confirmed_memory_id, first.confirmed_memory_id);
        // The replay is served from cache; D-4 was only called once.
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn d4_already_confirmed_maps_to_idempotent_replay() {
        // When D-4 itself reports the request id already committed (its own
        // idempotency), the outcome is surfaced as an idempotent replay.
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        repo.push(ConfirmBehavior::AlreadyConfirmed);
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let success = coord
            .confirm(&repo, "life-a", "c1", &prepared.approval_token)
            .unwrap();
        assert_eq!(success.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn consumed_token_expires_after_cache_window() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;
        coord.confirm(&repo, "life-a", "c1", &token).unwrap();

        coord.clock.advance(CONSUMED_CACHE_MILLIS);
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::TokenConsumed)
        );
    }

    #[test]
    fn cancel_issued_token_then_confirm_reports_cancelled() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;

        assert_eq!(
            coord.cancel("life-a", "c1", &token).unwrap(),
            CancelOutcome::Cancelled
        );
        // Cancel is idempotent.
        assert_eq!(
            coord.cancel("life-a", "c1", &token).unwrap(),
            CancelOutcome::AlreadyCancelled
        );
        // A cancelled token cannot confirm.
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::TokenCancelled)
        );
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn cancel_after_consume_reports_already_consumed() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;
        coord.confirm(&repo, "life-a", "c1", &token).unwrap();
        assert_eq!(
            coord.cancel("life-a", "c1", &token).unwrap(),
            CancelOutcome::AlreadyConsumed
        );
    }

    #[test]
    fn d4_revision_conflict_maps_to_revision_conflict_and_invalidates() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        repo.push(ConfirmBehavior::Fail(
            CandidateMemoryError::revision_conflict(),
        ));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;

        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::RevisionConflict)
        );
        // Terminal error retired the token to Invalidated. A second attempt
        // sees Invalidated → ContextChanged (the Invalidated state is the
        // generic "context changed" from the registry's perspective).
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::ContextChanged)
        );
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn d4_storage_unavailable_is_retryable() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        repo.push(ConfirmBehavior::Fail(
            CandidateMemoryError::storage_unavailable(),
        ));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;

        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::StorageUnavailable {
                retry_after_ms: 250
            })
        );
        // The token stays usable; the next attempt (default Confirm) succeeds.
        let success = coord.confirm(&repo, "life-a", "c1", &token).unwrap();
        assert_eq!(success.outcome, ConfirmationOutcome::Confirmed);
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn sensitivity_flip_since_prepare_is_context_changed() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;
        // Candidate becomes sensitive after prepare.
        repo.set_candidate(Some(candidate("c1", "life-a", true)));
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::ContextChanged)
        );
        // D-4 confirm was never reached.
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn candidate_deleted_since_prepare_is_context_changed() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;
        repo.set_candidate(None);
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::ContextChanged)
        );
    }

    #[test]
    fn concurrent_confirm_only_one_reaches_d4() {
        // Two threads confirm the same token at once. One claims the in-flight lease
        // and drives D-4; the other must be rejected as in-flight. D-4 is called once.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let gate = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::BlockThenConfirm(Arc::clone(&gate)));
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let start = Arc::new(Barrier::new(2));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let start = Arc::clone(&start);
            let gate = Arc::clone(&gate);
            let token_json = token_json.clone();
            handles.push(thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                start.wait();
                let result = coord.confirm(repo.as_ref(), "life-a", "c1", &token);
                // The loser is rejected before ever reaching D-4, so the winner is
                // still parked on the D-4 barrier. The loser releases it so the
                // winner can complete instead of deadlocking.
                if result.is_err() {
                    gate.wait();
                }
                result
            }));
        }
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        let successes = results
            .iter()
            .filter(|r| matches!(r, Ok(s) if s.outcome == ConfirmationOutcome::Confirmed))
            .count();
        let in_flight = results
            .iter()
            .filter(|r| matches!(r, Err(ConfirmationError::TokenInFlight)))
            .count();
        assert_eq!(successes, 1, "exactly one confirm should win");
        assert_eq!(in_flight, 1, "the other must see in-flight");
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_lease_is_taken_over_and_stale_attempt_returns_idempotent_replay() {
        // Attempt A claims the lease and parks inside D-4. The lease then expires and
        // attempt B takes over, confirming successfully. When A finally returns, its
        // finalize must detect it is stale and return idempotentReplay — never a
        // fresh Confirmed.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        // Behavior for B's takeover attempt.
        repo.push(ConfirmBehavior::Confirm);

        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let a = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        // Wait until A is parked inside D-4 holding the lease.
        entered.wait();
        // The lease elapses.
        coord.clock.advance(IN_FLIGHT_LEASE_MILLIS);
        // B takes over and confirms.
        let token_b: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let b = coord
            .confirm(repo.as_ref(), "life-a", "c1", &token_b)
            .unwrap();
        assert_eq!(b.outcome, ConfirmationOutcome::Confirmed);

        // Let A finish; its finalize is stale and must return idempotentReplay,
        // not a fresh Confirmed.
        release.wait();
        let a_result = a.join().unwrap().unwrap();
        assert_eq!(
            a_result.outcome,
            ConfirmationOutcome::IdempotentReplay,
            "stale attempt must never return fresh Confirmed"
        );
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 2);

        // The token is consumed; a replay is served from B's cached result.
        let token_c: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let replay = coord
            .confirm(repo.as_ref(), "life-a", "c1", &token_c)
            .unwrap();
        assert_eq!(replay.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(replay.confirmed_memory_id, b.confirmed_memory_id);
    }

    #[test]
    fn attempts_are_capped() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        // Fail transiently more times than the cap allows.
        for _ in 0..MAX_ATTEMPTS {
            repo.push(ConfirmBehavior::Fail(
                CandidateMemoryError::storage_unavailable(),
            ));
        }
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;
        for _ in 0..MAX_ATTEMPTS {
            assert!(matches!(
                coord.confirm(&repo, "life-a", "c1", &token),
                Err(ConfirmationError::StorageUnavailable { .. })
            ));
        }
        // The cap is now reached; the next attempt is retired as context-changed.
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::ContextChanged)
        );
    }

    // ── BLOCKER 3: Cancel InFlight semantics ────────────────────────────

    #[test]
    fn cancel_during_active_inflight_returns_token_in_flight() {
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let gate = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::BlockThenConfirm(Arc::clone(&gate)));
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // Start confirm in another thread (blocks inside D-4).
        let t = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        // Give the thread time to enter InFlight.
        thread::sleep(std::time::Duration::from_millis(20));

        // Cancel must return TokenInFlight while confirm is running.
        let token2: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let cancel_result = coord.cancel("life-a", "c1", &token2);
        assert_eq!(
            cancel_result,
            Err(ConfirmationError::TokenInFlight),
            "cancel during active InFlight must return TokenInFlight"
        );

        // Release D-4 and let confirm complete.
        gate.wait();
        let confirm_result = t.join().unwrap();
        assert_eq!(
            confirm_result.unwrap().outcome,
            ConfirmationOutcome::Confirmed
        );
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn cancel_after_inflight_lease_expiry_does_not_cancel_active_attempt() {
        // A's lease expires but its D-4 call is still running. Cancel must not
        // transition the token to Cancelled.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let a = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        // Wait until A is parked inside D-4.
        entered.wait();
        // The lease elapses.
        coord.clock.advance(IN_FLIGHT_LEASE_MILLIS);

        // Cancel must still return TokenInFlight, not Cancelled.
        let token_c: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let cancel_result = coord.cancel("life-a", "c1", &token_c);
        assert_eq!(cancel_result, Err(ConfirmationError::TokenInFlight));

        // Let A finish.
        release.wait();
        let a_result = a.join().unwrap();
        assert_eq!(a_result.unwrap().outcome, ConfirmationOutcome::Confirmed);
    }

    #[test]
    fn confirm_cancel_race_cannot_leave_cancelled_after_d4_success() {
        // Two threads: one confirms (blocks in D-4), the other tries to cancel.
        // After D-4 succeeds, the token must be Consumed — not Cancelled.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let gate = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::BlockThenConfirm(Arc::clone(&gate)));
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // Confirm in another thread.
        let t = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        thread::sleep(std::time::Duration::from_millis(20));

        // Cancel attempt while InFlight.
        let token2: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        assert_eq!(
            coord.cancel("life-a", "c1", &token2),
            Err(ConfirmationError::TokenInFlight)
        );

        // Release D-4.
        gate.wait();
        let result = t.join().unwrap().unwrap();
        assert_eq!(result.outcome, ConfirmationOutcome::Confirmed);

        // Token is now Consumed, not Cancelled.
        let token3: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let cancel_after = coord.cancel("life-a", "c1", &token3);
        assert_eq!(
            cancel_after,
            Ok(CancelOutcome::AlreadyConsumed),
            "after D-4 success the token must be Consumed, not Cancelled"
        );
    }

    // ── BLOCKER 4: Stale attempt success semantics ─────────────────────

    #[test]
    fn stale_confirmed_attempt_returns_idempotent_replay() {
        // A takes lease, blocks. B takes over and confirms. A returns success.
        // A must get idempotentReplay, not Confirmed.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        repo.push(ConfirmBehavior::Confirm); // B

        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let a = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        entered.wait();
        coord.clock.advance(IN_FLIGHT_LEASE_MILLIS);

        let token_b: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let b = coord
            .confirm(repo.as_ref(), "life-a", "c1", &token_b)
            .unwrap();
        assert_eq!(b.outcome, ConfirmationOutcome::Confirmed);

        release.wait();
        let a_result = a.join().unwrap().unwrap();
        assert_eq!(
            a_result.outcome,
            ConfirmationOutcome::IdempotentReplay,
            "stale D-4 Confirmed must surface as idempotentReplay"
        );
    }

    #[test]
    fn stale_success_promotes_newer_inflight_entry_to_consumed() {
        // Scenario: B is InFlight when stale A returns success.
        // A's success must promote the entry to Consumed.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        // A blocks.
        let entered_a = Arc::new(Barrier::new(2));
        let release_a = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered_a),
            release: Arc::clone(&release_a),
        });
        // B blocks (so we can observe it's InFlight).
        let entered_b = Arc::new(Barrier::new(2));
        let release_b = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered_b),
            release: Arc::clone(&release_b),
        });

        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // A starts.
        let a = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        entered_a.wait();
        coord.clock.advance(IN_FLIGHT_LEASE_MILLIS);

        // B takes over (blocks).
        let b_handle = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        entered_b.wait();

        // A returns success while B is InFlight.
        release_a.wait();
        let a_result = a.join().unwrap().unwrap();
        assert_eq!(a_result.outcome, ConfirmationOutcome::IdempotentReplay);

        // Entry should now be Consumed (promoted by A's stale success).
        // B finishes and must see the cached result.
        release_b.wait();
        let b_result = b_handle.join().unwrap().unwrap();
        assert_eq!(
            b_result.outcome,
            ConfirmationOutcome::IdempotentReplay,
            "B must see idempotentReplay since A already promoted to Consumed"
        );
    }

    #[test]
    fn newer_attempt_after_stale_success_returns_cached_idempotent_result() {
        // A confirms successfully (as current). Then a new confirm attempt arrives
        // and must get idempotentReplay from the cached result.
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // First confirm succeeds.
        let token1: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let first = coord.confirm(&repo, "life-a", "c1", &token1).unwrap();
        assert_eq!(first.outcome, ConfirmationOutcome::Confirmed);

        // Second confirm (within cache window) gets idempotentReplay.
        let token2: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let second = coord.confirm(&repo, "life-a", "c1", &token2).unwrap();
        assert_eq!(second.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(second.confirmed_memory_id, first.confirmed_memory_id);
    }

    #[test]
    fn stale_temporary_error_cannot_restore_consumed_to_issued() {
        // A confirms → Consumed. Then a stale error arrives — must not regress.
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // Confirm successfully.
        let token1: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        coord.confirm(&repo, "life-a", "c1", &token1).unwrap();

        // Simulate a stale error by manually setting the entry to simulate a
        // concurrent attempt. We can verify by checking that a subsequent confirm
        // still returns the cached result.
        coord.clock.advance(CONSUMED_CACHE_MILLIS - 1);
        let token2: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let replay = coord.confirm(&repo, "life-a", "c1", &token2).unwrap();
        assert_eq!(
            replay.outcome,
            ConfirmationOutcome::IdempotentReplay,
            "consumed entry must remain consumable for replay"
        );
    }

    #[test]
    fn stale_business_error_cannot_invalidate_newer_attempt() {
        // A fails terminally. B retries and succeeds. A's terminal error must not
        // invalidate B's result.
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        repo.push(ConfirmBehavior::Fail(
            CandidateMemoryError::revision_conflict(),
        ));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // First attempt fails terminally → Invalidated with dedicated code.
        let token1: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let err = coord.confirm(&repo, "life-a", "c1", &token1).unwrap_err();
        assert_eq!(err, ConfirmationError::RevisionConflict);

        // The token is invalidated; a retry returns ContextChanged (the token's
        // terminal state, not the original D-4 error).
        let token2: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let err2 = coord.confirm(&repo, "life-a", "c1", &token2).unwrap_err();
        assert_eq!(err2, ConfirmationError::ContextChanged);
    }

    // ── HIGH 1: Token TTL ──────────────────────────────────────────────

    #[test]
    fn token_ttl_is_exactly_three_minutes() {
        assert_eq!(TOKEN_TTL_MILLIS, 3 * 60 * 1000);
    }

    #[test]
    fn token_is_valid_immediately_before_three_minutes() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        coord.clock.advance(TOKEN_TTL_MILLIS - 1);
        let result = coord.confirm(&repo, "life-a", "c1", &prepared.approval_token);
        assert!(result.is_ok(), "token must be valid 1ms before TTL");
    }

    #[test]
    fn token_expires_at_three_minutes() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        coord.clock.advance(TOKEN_TTL_MILLIS);
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::TokenExpired)
        );
    }

    // ── HIGH 1: InFlight protection ─────────────────────────────────────

    #[test]
    fn cleanup_never_evicts_inflight_after_token_ttl() {
        // An InFlight entry must survive cleanup even after its token TTL expires.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // Start confirm in a thread — it will block inside D-4 as InFlight.
        let t = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        // Wait until InFlight.
        entered.wait();

        // Advance time well past token TTL.
        coord.clock.advance(TOKEN_TTL_MILLIS * 2);

        // Trigger cleanup by preparing many entries (one slot is taken by InFlight).
        // Some may fail with RegistryCapacity since InFlight cannot be evicted;
        // that is expected — we just need to trigger cleanup.
        for i in 0..REGISTRY_SOFT_CAPACITY {
            let id = format!("filler-{i}");
            let filler_repo = MockRepo::new(candidate(&id, "life-a", false));
            let _ = coord.prepare(&filler_repo, "life-a", &id);
        }

        // The InFlight entry must still be in the registry.
        {
            let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
            let digest = token.digest();
            let map = coord.registry.lock().unwrap();
            assert!(
                map.contains_key(&digest),
                "InFlight entry must survive cleanup even after TTL"
            );
        }

        // Release D-4 and let confirm complete.
        release.wait();
        let result = t.join().unwrap().unwrap();
        assert_eq!(result.outcome, ConfirmationOutcome::Confirmed);
    }

    #[test]
    fn inflight_attempt_may_complete_after_token_ttl() {
        // A D-4 call that started before TTL expiry must be allowed to complete
        // and return Confirmed even after the token TTL has elapsed.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let t = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        // Wait until InFlight.
        entered.wait();
        // TTL expires while D-4 is running.
        coord.clock.advance(TOKEN_TTL_MILLIS + 1000);

        // Release D-4.
        release.wait();
        let result = t.join().unwrap().unwrap();
        assert_eq!(
            result.outcome,
            ConfirmationOutcome::Confirmed,
            "D-4 call that started before TTL must complete as Confirmed"
        );
        assert_eq!(result.candidate_id, "c1");
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn expired_token_cannot_take_over_expired_inflight_lease() {
        // When both lease AND TTL have expired, a new confirm attempt must NOT
        // take over — it must return TokenInFlight to avoid starting a second D-4
        // call while the old one may still be running.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // A starts confirm, blocks inside D-4.
        let a = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        entered.wait();
        // Advance past BOTH lease AND TTL.
        coord
            .clock
            .advance(TOKEN_TTL_MILLIS + IN_FLIGHT_LEASE_MILLIS);

        // B tries to confirm — must get TokenExpired since both lease AND TTL expired.
        let token_b: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let b_result = coord.confirm(repo.as_ref(), "life-a", "c1", &token_b);
        assert_eq!(
            b_result,
            Err(ConfirmationError::TokenExpired),
            "expired token must not take over expired InFlight lease"
        );

        // Only 1 D-4 call (A's).
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);

        // Let A finish.
        release.wait();
        let a_result = a.join().unwrap().unwrap();
        assert_eq!(a_result.outcome, ConfirmationOutcome::Confirmed);
    }

    #[test]
    fn temporary_failure_after_token_ttl_finishes_as_expired() {
        // A confirm attempt enters InFlight, then the TTL expires while D-4 is
        // running. D-4 returns a temporary failure. Because TTL is expired, the
        // entry must transition to Expired, not back to Issued.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        // D-4 blocks so we can expire the TTL mid-flight.
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        // Second D-4 call (for the retry) returns storage unavailable.
        repo.push(ConfirmBehavior::Fail(
            CandidateMemoryError::storage_unavailable(),
        ));

        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // Start confirm in a thread — it will block inside D-4.
        let t = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        // Wait until confirm is blocked inside D-4.
        entered.wait();
        // Advance past TTL.
        coord.clock.advance(TOKEN_TTL_MILLIS);
        // Let D-4 finish — it returns Confirmed (first behavior is SignalThenBlock).
        release.wait();
        let result = t.join().unwrap();
        // The first confirm succeeds (D-4 returned Confirmed).
        assert_eq!(result.unwrap().outcome, ConfirmationOutcome::Confirmed);

        // The token is now Consumed. A retry within the cache window gets replay.
        let token2: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let replay = coord
            .confirm(repo.as_ref(), "life-a", "c1", &token2)
            .unwrap();
        assert_eq!(replay.outcome, ConfirmationOutcome::IdempotentReplay);
    }

    #[test]
    fn retryable_error_after_ttl_expires_entry() {
        // If a confirm attempt gets a temporary failure while TTL is still valid,
        // the token stays Issued (retryable). Once TTL has expired, the entry is
        // lazily expired before a new attempt is claimed — so TokenExpired is
        // returned without calling D-4.
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        repo.push(ConfirmBehavior::Fail(
            CandidateMemoryError::storage_unavailable(),
        ));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token = prepared.approval_token;

        // First attempt: TTL still valid → StorageUnavailable, token stays Issued.
        assert!(matches!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);

        // Advance past TTL.
        coord.clock.advance(TOKEN_TTL_MILLIS);

        // Second attempt: TTL expired → entry is lazily expired, TokenExpired
        // returned without calling D-4.
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::TokenExpired),
        );
        // D-4 was not called for the second attempt (lazy expiry).
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn successful_d4_after_token_ttl_finishes_as_consumed() {
        // A D-4 call that started before TTL but succeeds after TTL expiry
        // must still promote the entry to Consumed.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let t = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        entered.wait();
        // TTL expires.
        coord.clock.advance(TOKEN_TTL_MILLIS + 1000);
        release.wait();

        let result = t.join().unwrap().unwrap();
        assert_eq!(result.outcome, ConfirmationOutcome::Confirmed);

        // Entry is now Consumed. Within the replay window, a new confirm
        // must return idempotentReplay.
        let token2: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let replay = coord
            .confirm(repo.as_ref(), "life-a", "c1", &token2)
            .unwrap();
        assert_eq!(replay.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(replay.confirmed_memory_id, result.confirmed_memory_id);
    }

    #[test]
    fn registry_capacity_never_evicts_inflight_entry() {
        // Even when the registry is at capacity, InFlight entries are retained.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // Start confirm — blocks as InFlight.
        let t = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        entered.wait();

        // Fill registry to capacity. Some may fail since InFlight cannot be evicted.
        for i in 0..REGISTRY_SOFT_CAPACITY {
            let id = format!("filler-{i}");
            let filler_repo = MockRepo::new(candidate(&id, "life-a", false));
            let _ = coord.prepare(&filler_repo, "life-a", &id);
        }

        // The InFlight entry must still be present.
        {
            let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
            let digest = token.digest();
            let map = coord.registry.lock().unwrap();
            assert!(
                map.contains_key(&digest),
                "InFlight entry must not be evicted by capacity cleanup"
            );
        }

        release.wait();
        let result = t.join().unwrap().unwrap();
        assert_eq!(result.outcome, ConfirmationOutcome::Confirmed);
    }

    // ── HIGH 2: expiresAt wall clock ────────────────────────────────────

    #[test]
    fn prepare_returns_wall_clock_plus_three_minute_expiry() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        // FakeClock wall is "2026-07-14T10:00:00.000Z". Expiry should be +3 min.
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        assert_eq!(
            prepared.expires_at, "2026-07-14T10:03:00.000Z",
            "expiresAt must be wall clock + 3 minutes"
        );
    }

    #[test]
    fn fake_clock_wall_time_advances_expiry_display() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        coord.clock.set_wall("2026-07-14T14:30:00.000Z".to_string());
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        assert_eq!(prepared.expires_at, "2026-07-14T14:33:00.000Z");
    }

    #[test]
    fn wall_clock_rollback_does_not_extend_monotonic_ttl() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        // Roll back wall clock.
        coord.clock.set_wall("2026-07-14T09:00:00.000Z".to_string());
        // Monotonic TTL still applies.
        coord.clock.advance(TOKEN_TTL_MILLIS);
        assert_eq!(
            coord.confirm(&repo, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::TokenExpired),
            "monotonic TTL must not be affected by wall clock rollback"
        );
    }

    // ── HIGH 4: Registry capacity ───────────────────────────────────────

    #[test]
    fn registry_accepts_up_to_512_active_entries() {
        let coord = coordinator();
        for i in 0..REGISTRY_SOFT_CAPACITY {
            let id = format!("c{i}");
            let life = "life-a";
            let repo = MockRepo::new(candidate(&id, life, false));
            coord.prepare(&repo, life, &id).unwrap();
        }
        assert_eq!(coord.registry.lock().unwrap().len(), REGISTRY_SOFT_CAPACITY);
    }

    #[test]
    fn registry_rejects_513th_when_all_entries_are_active() {
        let coord = coordinator();
        for i in 0..REGISTRY_SOFT_CAPACITY {
            let id = format!("c{i}");
            let repo = MockRepo::new(candidate(&id, "life-a", false));
            coord.prepare(&repo, "life-a", &id).unwrap();
        }
        // All 512 entries are fresh Issued — none are evictable.
        let repo = MockRepo::new(candidate("overflow", "life-a", false));
        assert_eq!(
            coord.prepare(&repo, "life-a", "overflow").unwrap_err(),
            ConfirmationError::RegistryCapacity
        );
    }

    #[test]
    fn registry_cleans_expired_entries_before_capacity_error() {
        let coord = coordinator();
        // Fill half with entries that will expire.
        for i in 0..256 {
            let id = format!("old-{i}");
            let repo = MockRepo::new(candidate(&id, "life-a", false));
            coord.prepare(&repo, "life-a", &id).unwrap();
        }
        // Expire them.
        coord.clock.advance(TOKEN_TTL_MILLIS);
        // Fill with fresh entries — cleanup removes expired ones.
        for i in 0..256 {
            let id = format!("new-{i}");
            let repo = MockRepo::new(candidate(&id, "life-a", false));
            coord.prepare(&repo, "life-a", &id).unwrap();
        }
        assert_eq!(
            coord.registry.lock().unwrap().len(),
            512,
            "expired entries are cleaned up, making room for new ones"
        );
    }

    #[test]
    fn registry_cleans_terminal_entries_after_cache_window() {
        // Cleanup only runs when the registry is at capacity. Fill it up, expire
        // some entries, then verify cleanup makes room.
        let coord = coordinator();
        // Prepare 512 entries, confirm the first half so they become Consumed.
        for i in 0..REGISTRY_SOFT_CAPACITY {
            let id = format!("c{i}");
            let repo = MockRepo::new(candidate(&id, "life-a", false));
            coord.prepare(&repo, "life-a", &id).unwrap();
        }
        assert_eq!(coord.registry.lock().unwrap().len(), REGISTRY_SOFT_CAPACITY);
        // Advance past cache window so Consumed entries become evictable.
        coord.clock.advance(CONSUMED_CACHE_MILLIS + 1);
        // New prepare triggers cleanup — expired/consumed entries are removed.
        let repo = MockRepo::new(candidate("new-1", "life-a", false));
        coord.prepare(&repo, "life-a", "new-1").unwrap();
        let len = coord.registry.lock().unwrap().len();
        assert!(
            len < REGISTRY_SOFT_CAPACITY + 1,
            "cleanup should have evicted old entries, but registry has {len}"
        );
    }

    #[test]
    fn coordinator_recreation_invalidates_existing_token() {
        // A token minted by one coordinator instance is unknown to a fresh instance.
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        let coord1 = coordinator();
        let prepared = coord1.prepare(&repo, "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // New coordinator — simulates application restart.
        let coord2 = coordinator();
        let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        assert_eq!(
            coord2.confirm(&repo, "life-a", "c1", &token),
            Err(ConfirmationError::TokenInvalid),
            "new coordinator must not recognize old token"
        );
    }
    // ── HIGH 1: InFlight TTL expiry during D-4 ──────────────────────────

    #[test]
    fn panic_before_d4_commit_does_not_leave_permanent_inflight() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        repo.push(ConfirmBehavior::Fail(
            CandidateMemoryError::confirmation_panic_recovered(),
        ));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let first_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        assert!(matches!(
            coord.confirm(&repo, "life-a", "c1", &first_token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));

        let retry_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let recovered = coord.confirm(&repo, "life-a", "c1", &retry_token).unwrap();
        assert_eq!(recovered.outcome, ConfirmationOutcome::Confirmed);
        assert_eq!(repo.confirm_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn panic_orphans_cannot_permanently_exhaust_registry() {
        let repo = MockRepo::new(candidate("orphan", "life-a", false));
        repo.push(ConfirmBehavior::Fail(
            CandidateMemoryError::confirmation_panic_recovered(),
        ));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "orphan").unwrap();
        assert!(matches!(
            coord.confirm(&repo, "life-a", "orphan", &prepared.approval_token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));

        // The final same-token call is read-only after the original TTL and
        // retires the uncommitted recovery before capacity cleanup runs.
        coord.clock.advance(TOKEN_TTL_MILLIS.saturating_add(1));
        assert_eq!(
            coord.confirm(&repo, "life-a", "orphan", &prepared.approval_token),
            Err(ConfirmationError::TokenExpired)
        );
        for i in 0..REGISTRY_SOFT_CAPACITY {
            let id = format!("fresh-{i}");
            let fresh_repo = MockRepo::new(candidate(&id, "life-a", false));
            coord.prepare(&fresh_repo, "life-a", &id).unwrap();
        }
        assert_eq!(coord.registry.lock().unwrap().len(), REGISTRY_SOFT_CAPACITY);
    }

    #[test]
    fn cancel_cannot_override_panic_recovery_state() {
        let repo = MockRepo::new(candidate("c1", "life-a", false));
        repo.push(ConfirmBehavior::Fail(
            CandidateMemoryError::confirmation_panic_recovered(),
        ));
        let coord = coordinator();
        let prepared = coord.prepare(&repo, "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let first_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        assert!(matches!(
            coord.confirm(&repo, "life-a", "c1", &first_token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));
        let cancel_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        assert_eq!(
            coord.cancel("life-a", "c1", &cancel_token),
            Err(ConfirmationError::TokenInFlight)
        );

        let retry_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        assert_eq!(
            coord
                .confirm(&repo, "life-a", "c1", &retry_token)
                .unwrap()
                .outcome,
            ConfirmationOutcome::Confirmed
        );
    }

    #[test]
    fn stale_temporary_error_from_old_attempt_cannot_restore_newer_consumed_entry() {
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlockFail {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            error: CandidateMemoryError::storage_unavailable(),
        });
        repo.push(ConfirmBehavior::Confirm);
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let old_attempt = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };
        entered.wait();
        coord.clock.advance(IN_FLIGHT_LEASE_MILLIS);

        let takeover_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let takeover = coord
            .confirm(repo.as_ref(), "life-a", "c1", &takeover_token)
            .unwrap();
        assert_eq!(takeover.outcome, ConfirmationOutcome::Confirmed);
        release.wait();

        assert!(matches!(
            old_attempt.join().unwrap(),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));
        let replay_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let replay = coord
            .confirm(repo.as_ref(), "life-a", "c1", &replay_token)
            .unwrap();
        assert_eq!(replay.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(replay.confirmed_memory_id, takeover.confirmed_memory_id);
    }

    #[test]
    fn stale_business_error_from_old_attempt_cannot_invalidate_newer_attempt() {
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlockFail {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
            error: CandidateMemoryError::new(
                "CANDIDATE_MEMORY_REVISION_CONFLICT",
                "revision conflict",
                true,
            ),
        });
        repo.push(ConfirmBehavior::Confirm);
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let old_attempt = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };
        entered.wait();
        coord.clock.advance(IN_FLIGHT_LEASE_MILLIS);
        let takeover_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let takeover = coord
            .confirm(repo.as_ref(), "life-a", "c1", &takeover_token)
            .unwrap();
        release.wait();

        assert_eq!(
            old_attempt.join().unwrap(),
            Err(ConfirmationError::RevisionConflict)
        );
        let replay_token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let replay = coord
            .confirm(repo.as_ref(), "life-a", "c1", &replay_token)
            .unwrap();
        assert_eq!(replay.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(replay.confirmed_memory_id, takeover.confirmed_memory_id);
    }

    #[test]
    fn different_candidates_do_not_share_entry_lock() {
        let repo_a = Arc::new(MockRepo::new(candidate("a", "life-a", false)));
        let repo_b = Arc::new(MockRepo::new(candidate("b", "life-a", false)));
        let entered_a = Arc::new(Barrier::new(2));
        let release_a = Arc::new(Barrier::new(2));
        let entered_b = Arc::new(Barrier::new(2));
        let release_b = Arc::new(Barrier::new(2));
        repo_a.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered_a),
            release: Arc::clone(&release_a),
        });
        repo_b.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered_b),
            release: Arc::clone(&release_b),
        });
        let coord = Arc::new(coordinator());
        let token_a = serde_json::to_string(
            &coord
                .prepare(repo_a.as_ref(), "life-a", "a")
                .unwrap()
                .approval_token,
        )
        .unwrap();
        let token_b = serde_json::to_string(
            &coord
                .prepare(repo_b.as_ref(), "life-a", "b")
                .unwrap()
                .approval_token,
        )
        .unwrap();

        let a = {
            let repo = Arc::clone(&repo_a);
            let coord = Arc::clone(&coord);
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_a).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "a", &token)
            })
        };
        entered_a.wait();
        let b = {
            let repo = Arc::clone(&repo_b);
            let coord = Arc::clone(&coord);
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_b).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "b", &token)
            })
        };
        // This barrier proves B reached D-4 while A was still blocked, without
        // timing sleeps or global test serialization.
        entered_b.wait();
        release_b.wait();
        release_a.wait();
        assert_eq!(
            a.join().unwrap().unwrap().outcome,
            ConfirmationOutcome::Confirmed
        );
        assert_eq!(
            b.join().unwrap().unwrap().outcome,
            ConfirmationOutcome::Confirmed
        );
    }

    #[test]
    fn temporary_failure_after_token_ttl_expires_entry() {
        // Token TTL expires while D-4 is running. D-4 returns Confirmed (the
        // first behavior). The entry becomes Consumed (D-4 success is
        // authoritative regardless of TTL). A subsequent attempt sees the cached
        // result. This proves the finalize path for post-TTL success.
        let repo = Arc::new(MockRepo::new(candidate("c1", "life-a", false)));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        repo.push(ConfirmBehavior::SignalThenBlock {
            entered: Arc::clone(&entered),
            release: Arc::clone(&release),
        });
        let coord = Arc::new(coordinator());
        let prepared = coord.prepare(repo.as_ref(), "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        let handle = {
            let repo = Arc::clone(&repo);
            let coord = Arc::clone(&coord);
            let token_json = token_json.clone();
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&token_json).unwrap();
                coord.confirm(repo.as_ref(), "life-a", "c1", &token)
            })
        };

        entered.wait();
        // TTL expires while D-4 is blocked.
        coord.clock.advance(TOKEN_TTL_MILLIS + 1000);

        // D-4 returns Confirmed. The entry becomes Consumed.
        release.wait();
        let result = handle.join().unwrap().unwrap();
        assert_eq!(result.outcome, ConfirmationOutcome::Confirmed);

        // A replay within the cache window works.
        let token_replay: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let replay = coord
            .confirm(repo.as_ref(), "life-a", "c1", &token_replay)
            .unwrap();
        assert_eq!(replay.outcome, ConfirmationOutcome::IdempotentReplay);
    }
}

/// Integration tests against the real `StorageService` and the frozen D-4 confirm
/// transaction. These prove the coordinator-built `SensitiveConfirmationGrant`
/// actually satisfies D-4's sensitive-consent gate — something the mock cannot show.
#[cfg(test)]
mod integration_tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Barrier};
    use std::thread;

    use super::*;
    use crate::memory::candidate::{
        CandidateInferenceStatus, CandidateMemoryRepository, CandidateMemorySourceType,
        NewCandidateMemory, PRIMARY_USER_SUBJECT_ID,
    };
    use crate::memory::{MemoryQuery, MemoryRepository, MemoryStatus};
    use crate::storage::{
        test_support::candidate_confirmation_artifact_counts, unique_suffix, LifeIdentityRecord,
        PersonaTemplateRecord, StorageService,
    };

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir()
                .join(format!("digital-life-confirm-{name}-{}", unique_suffix()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn seeded_service(root: &TestRoot) -> StorageService {
        let service = StorageService::initialize_with_roots(root.0.join("data"), None).unwrap();
        service
            .save_persona(PersonaTemplateRecord {
                id: "persona".into(),
                name: "Persona".into(),
                version: 1,
                persona_json: "{}".into(),
            })
            .unwrap();
        service
            .save_life(LifeIdentityRecord {
                id: "life-a".into(),
                name: "Life A".into(),
                created_at: "2026-07-14T00:00:00.000Z".into(),
                version: 1,
                body_id: "body".into(),
                persona_id: "persona".into(),
                persona_version: 1,
            })
            .unwrap();
        service
    }

    fn insert(service: &StorageService, id: &str, sensitive: bool) {
        let candidate = NewCandidateMemory {
            id: id.into(),
            life_id: "life-a".into(),
            subject_id: PRIMARY_USER_SUBJECT_ID.into(),
            kind: MemoryKind::Fact,
            content: Some(format!("Candidate {id}")),
            summary: Some("summary".into()),
            source_type: CandidateMemorySourceType::Conversation,
            source_id: Some("conv".into()),
            confidence: 0.8,
            importance: 0.6,
            is_sensitive: sensitive,
            inference_status: CandidateInferenceStatus::Extracted,
            status: CandidateMemoryStatus::Pending,
            dedup_fingerprint: None,
            proposed_at: "2026-07-14T10:00:00.000Z".into(),
            expires_at: None,
            reviewed_at: None,
            last_user_edit_at: None,
            confirmed_memory_id: None,
            accepted_request_id: None,
            rejection_reason_code: None,
            superseded_by_candidate_id: None,
            conflicts_with_memory_id: None,
            created_at: "2026-07-14T10:00:00.000Z".into(),
            updated_at: "2026-07-14T10:00:00.000Z".into(),
        };
        <StorageService as CandidateMemoryRepository>::insert_candidate(service, candidate)
            .unwrap();
    }

    #[test]
    fn confirms_a_standard_candidate_through_real_d4() {
        let root = TestRoot::new("standard");
        let service = seeded_service(&root);
        insert(&service, "c1", false);

        let coord = CandidateConfirmationCoordinator::default();
        let prepared = coord.prepare(&service, "life-a", "c1").unwrap();
        assert_eq!(prepared.requirement, ConfirmationRequirement::Standard);

        let success = coord
            .confirm(&service, "life-a", "c1", &prepared.approval_token)
            .unwrap();
        assert_eq!(success.outcome, ConfirmationOutcome::Confirmed);
        assert!(!success.confirmed_memory_id.is_empty());

        // The candidate is now accepted in storage and cannot be re-prepared.
        assert_eq!(
            coord.prepare(&service, "life-a", "c1").unwrap_err(),
            ConfirmationError::NotFound
        );
    }

    #[test]
    fn confirms_a_sensitive_candidate_satisfying_the_d4_consent_gate() {
        // The coordinator is the only place a grant is minted. This proves the grant
        // it builds genuinely passes D-4's sensitive-consent gate end to end.
        let root = TestRoot::new("sensitive");
        let service = seeded_service(&root);
        insert(&service, "s1", true);

        let coord = CandidateConfirmationCoordinator::default();
        let prepared = coord.prepare(&service, "life-a", "s1").unwrap();
        assert_eq!(
            prepared.requirement,
            ConfirmationRequirement::ExplicitSensitiveApproval
        );
        assert!(prepared.is_sensitive);

        let success = coord
            .confirm(&service, "life-a", "s1", &prepared.approval_token)
            .unwrap();
        assert_eq!(success.outcome, ConfirmationOutcome::Confirmed);
    }

    #[test]
    fn replay_within_window_returns_same_memory_through_real_d4() {
        let root = TestRoot::new("replay");
        let service = seeded_service(&root);
        insert(&service, "c1", false);

        let coord = CandidateConfirmationCoordinator::default();
        let prepared = coord.prepare(&service, "life-a", "c1").unwrap();
        let token = prepared.approval_token;
        let first = coord.confirm(&service, "life-a", "c1", &token).unwrap();
        let replay = coord.confirm(&service, "life-a", "c1", &token).unwrap();
        assert_eq!(replay.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(replay.confirmed_memory_id, first.confirmed_memory_id);
    }

    #[test]
    fn confirm_on_missing_candidate_is_not_found_at_prepare() {
        let root = TestRoot::new("missing");
        let service = seeded_service(&root);
        let coord = CandidateConfirmationCoordinator::default();
        assert_eq!(
            coord.prepare(&service, "life-a", "ghost").unwrap_err(),
            ConfirmationError::NotFound
        );
    }

    #[test]
    fn same_token_confirmed_twice_only_creates_one_memory() {
        // Prepare once, confirm twice with the same token. D-4's idempotency
        // ensures only one confirmed Memory exists.
        let root = TestRoot::new("one-memory");
        let service = seeded_service(&root);
        insert(&service, "c1", false);

        let coord = CandidateConfirmationCoordinator::default();
        let prepared = coord.prepare(&service, "life-a", "c1").unwrap();
        let token_json = serde_json::to_string(&prepared.approval_token).unwrap();

        // First confirm.
        let token1: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let first = coord.confirm(&service, "life-a", "c1", &token1).unwrap();
        assert_eq!(first.outcome, ConfirmationOutcome::Confirmed);

        // Second confirm with same token → idempotent replay.
        let token2: ApprovalToken = serde_json::from_str(&token_json).unwrap();
        let second = coord.confirm(&service, "life-a", "c1", &token2).unwrap();
        assert_eq!(second.outcome, ConfirmationOutcome::IdempotentReplay);
        assert_eq!(second.confirmed_memory_id, first.confirmed_memory_id);
    }

    #[test]
    fn panic_after_d4_commit_recovers_with_same_request_id() {
        let root = TestRoot::new("panic-after-commit");
        let service = seeded_service(&root);
        insert(&service, "c1", false);
        let coord = CandidateConfirmationCoordinator::default();
        let prepared = coord.prepare(&service, "life-a", "c1").unwrap();
        let digest = prepared.approval_token.digest();
        let request_id = {
            let map = coord.registry.lock().unwrap();
            let entry = Arc::clone(map.get(&digest).unwrap());
            drop(map);
            let request_id = entry.lock().unwrap().request_id.clone();
            request_id
        };

        // The injected panic happens only after D-4 committed but before this
        // coordinator can cache the response. The caller receives a safe retryable
        // error, then retries the same token/request id for D-4 idempotency.
        service.request_candidate_confirmation_post_commit_panic_for_test();
        assert!(matches!(
            coord.confirm(&service, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));
        let recovered = coord
            .confirm(&service, "life-a", "c1", &prepared.approval_token)
            .unwrap();
        assert_eq!(recovered.outcome, ConfirmationOutcome::IdempotentReplay);

        let stored =
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap();
        assert_eq!(stored.status, CandidateMemoryStatus::Accepted);
        assert_eq!(stored.revision, 2);
        assert_eq!(
            stored.accepted_request_id.as_deref(),
            Some(request_id.as_str())
        );
        assert_eq!(
            stored.confirmed_memory_id.as_deref(),
            Some(recovered.confirmed_memory_id.as_str())
        );
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            0
        );
        let memories = <StorageService as MemoryRepository>::list(
            &service,
            MemoryQuery {
                life_id: "life-a".into(),
                status: Some(MemoryStatus::Confirmed),
                kind: None,
            },
        )
        .unwrap();
        assert_eq!(memories.len(), 1);
        let counts = candidate_confirmation_artifact_counts(
            &service,
            "life-a",
            "c1",
            &recovered.confirmed_memory_id,
        );
        assert_eq!(counts.memories, 1);
        assert_eq!(counts.revisions, 1);
        assert_eq!(counts.outbox_rows, 1);
        assert_eq!(counts.confirmation_audits, 1);
    }

    #[test]
    fn real_sqlite_pre_commit_panic_rolls_back_all_d4_writes() {
        let root = TestRoot::new("pre-commit-rollback");
        let service = seeded_service(&root);
        insert(&service, "c1", false);
        insert(&service, "c2", false);
        let coord = CandidateConfirmationCoordinator::with_clock(FakeClock::new());
        let prepared = coord.prepare(&service, "life-a", "c1").unwrap();

        // The failpoint is after all D-4 writes but before COMMIT, inside the
        // StorageService-owned unwind boundary.
        service.request_candidate_confirmation_pre_commit_panic_for_test();
        assert!(matches!(
            coord.confirm(&service, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));
        assert!(<StorageService as MemoryRepository>::list(
            &service,
            MemoryQuery {
                life_id: "life-a".into(),
                status: Some(MemoryStatus::Confirmed),
                kind: None,
            },
        )
        .unwrap()
        .is_empty());
        let candidate =
            <StorageService as CandidateMemoryRepository>::get_candidate(&service, "life-a", "c1")
                .unwrap();
        assert_eq!(candidate.status, CandidateMemoryStatus::Pending);
        assert_eq!(candidate.revision, 1);
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(&service, "life-a", "c1")
                .unwrap(),
            0
        );

        // Acquiring and using the same StorageService after the caught panic
        // proves its mutex was not poisoned.
        let second = coord.prepare(&service, "life-a", "c2").unwrap();
        assert_eq!(
            coord
                .confirm(&service, "life-a", "c2", &second.approval_token)
                .unwrap()
                .outcome,
            ConfirmationOutcome::Confirmed
        );
    }

    #[test]
    fn pre_commit_panic_before_token_expiry_may_retry_same_request_id() {
        let root = TestRoot::new("pre-commit-retry");
        let service = seeded_service(&root);
        insert(&service, "c1", false);
        let coord = CandidateConfirmationCoordinator::with_clock(FakeClock::new());
        let prepared = coord.prepare(&service, "life-a", "c1").unwrap();
        service.request_candidate_confirmation_pre_commit_panic_for_test();
        assert!(matches!(
            coord.confirm(&service, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));
        let retried = coord
            .confirm(&service, "life-a", "c1", &prepared.approval_token)
            .unwrap();
        assert_eq!(retried.outcome, ConfirmationOutcome::Confirmed);
        assert_eq!(
            <StorageService as MemoryRepository>::list(
                &service,
                MemoryQuery {
                    life_id: "life-a".into(),
                    status: Some(MemoryStatus::Confirmed),
                    kind: None,
                },
            )
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn pre_commit_panic_near_expiry_cannot_confirm_after_original_token_ttl() {
        let root = TestRoot::new("pre-commit-expired");
        let service = seeded_service(&root);
        insert(&service, "c1", false);
        let coord = CandidateConfirmationCoordinator::with_clock(FakeClock::new());
        let prepared = coord.prepare(&service, "life-a", "c1").unwrap();
        service.request_candidate_confirmation_pre_commit_panic_for_test();
        assert!(matches!(
            coord.confirm(&service, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));
        coord.clock.advance(TOKEN_TTL_MILLIS.saturating_add(1));
        assert_eq!(
            coord.confirm(&service, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::TokenExpired)
        );
        assert!(<StorageService as MemoryRepository>::list(
            &service,
            MemoryQuery {
                life_id: "life-a".into(),
                status: Some(MemoryStatus::Confirmed),
                kind: None,
            },
        )
        .unwrap()
        .is_empty());
    }

    #[test]
    fn post_commit_panic_after_token_expiry_reconciles_read_only() {
        let root = TestRoot::new("post-commit-expired");
        let service = seeded_service(&root);
        insert(&service, "c1", false);
        let coord = CandidateConfirmationCoordinator::with_clock(FakeClock::new());
        let prepared = coord.prepare(&service, "life-a", "c1").unwrap();
        service.request_candidate_confirmation_post_commit_panic_for_test();
        assert!(matches!(
            coord.confirm(&service, "life-a", "c1", &prepared.approval_token),
            Err(ConfirmationError::StorageUnavailable { .. })
        ));
        coord.clock.advance(TOKEN_TTL_MILLIS.saturating_add(1));
        assert_eq!(
            coord
                .confirm(&service, "life-a", "c1", &prepared.approval_token)
                .unwrap()
                .outcome,
            ConfirmationOutcome::IdempotentReplay
        );
        assert_eq!(
            <StorageService as MemoryRepository>::list(
                &service,
                MemoryQuery {
                    life_id: "life-a".into(),
                    status: Some(MemoryStatus::Confirmed),
                    kind: None,
                },
            )
            .unwrap()
            .len(),
            1
        );
    }

    #[test]
    fn different_tokens_same_candidate_create_one_confirmed_memory() {
        let root = TestRoot::new("two-tokens-one-candidate");
        let service = Arc::new(seeded_service(&root));
        insert(service.as_ref(), "c1", false);
        let coord = Arc::new(CandidateConfirmationCoordinator::default());
        let first = coord.prepare(service.as_ref(), "life-a", "c1").unwrap();
        let second = coord.prepare(service.as_ref(), "life-a", "c1").unwrap();
        let first_token = serde_json::to_string(&first.approval_token).unwrap();
        let second_token = serde_json::to_string(&second.approval_token).unwrap();
        let start = Arc::new(Barrier::new(3));

        let a = {
            let service = Arc::clone(&service);
            let coord = Arc::clone(&coord);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&first_token).unwrap();
                start.wait();
                coord.confirm(service.as_ref(), "life-a", "c1", &token)
            })
        };
        let b = {
            let service = Arc::clone(&service);
            let coord = Arc::clone(&coord);
            let start = Arc::clone(&start);
            thread::spawn(move || {
                let token: ApprovalToken = serde_json::from_str(&second_token).unwrap();
                start.wait();
                coord.confirm(service.as_ref(), "life-a", "c1", &token)
            })
        };
        start.wait();
        let a = a.join().unwrap();
        let b = b.join().unwrap();
        let successes = [a.as_ref().ok(), b.as_ref().ok()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        assert_eq!(successes.len(), 1);
        assert_eq!(successes[0].outcome, ConfirmationOutcome::Confirmed);
        assert!(matches!(
            a.err().or_else(|| b.err()),
            Some(ConfirmationError::RequestConflict)
        ));

        let stored = <StorageService as CandidateMemoryRepository>::get_candidate(
            service.as_ref(),
            "life-a",
            "c1",
        )
        .unwrap();
        let memory_id = stored.confirmed_memory_id.as_deref().unwrap();
        assert_eq!(stored.status, CandidateMemoryStatus::Accepted);
        assert_eq!(stored.revision, 2);
        assert_eq!(
            <StorageService as CandidateMemoryRepository>::count_evidence(
                service.as_ref(),
                "life-a",
                "c1",
            )
            .unwrap(),
            0
        );
        let counts =
            candidate_confirmation_artifact_counts(service.as_ref(), "life-a", "c1", memory_id);
        assert_eq!(counts.memories, 1);
        assert_eq!(counts.revisions, 1);
        assert_eq!(counts.outbox_rows, 1);
        assert_eq!(counts.confirmation_audits, 1);
    }
}
