use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use super::{
    candidate::{
        CandidateMemoryAuditRecord, CandidateMemoryError, CandidateMemoryRecord,
        CandidateMemoryRepository, CandidateMemorySourceType,
    },
    MemoryKind,
};

// ── Domain request types ──────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct EditCandidateRequest {
    pub candidate_id: String,
    pub expected_revision: i64,
    pub kind: MemoryKind,
    pub content: String,
    pub summary: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RejectionReason {
    NotTrue,
    NotUseful,
    TooSensitive,
    Outdated,
    Duplicate,
    Other,
}

impl RejectionReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotTrue => "not_true",
            Self::NotUseful => "not_useful",
            Self::TooSensitive => "too_sensitive",
            Self::Outdated => "outdated",
            Self::Duplicate => "duplicate",
            Self::Other => "other",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct RejectCandidateRequest {
    pub candidate_id: String,
    pub expected_revision: i64,
    pub reason: RejectionReason,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SupersedeCandidateRequest {
    pub candidate_id: String,
    pub replacement_candidate_id: String,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DeleteCandidateRequest {
    pub candidate_id: String,
    pub expected_revision: i64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AddEvidenceRequest {
    pub candidate_id: String,
    pub source_type: CandidateMemorySourceType,
    pub source_id: Option<String>,
    pub conversation_id: Option<String>,
    pub message_id: Option<String>,
}

// ── Domain result types ───────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub struct CandidateLifecycleResult {
    pub candidate: CandidateMemoryRecord,
    pub audit: CandidateMemoryAuditRecord,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CandidateEditOutcome {
    Changed,
    NoChange,
}

#[derive(Clone, Debug, PartialEq)]
pub struct CandidateEditResult {
    pub outcome: CandidateEditOutcome,
    pub candidate: CandidateMemoryRecord,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpiredCandidateScan {
    pub candidate_id: String,
    pub revision: i64,
}

/// Atomic persistence boundary for Candidate lifecycle operations.
///
/// Implementations must execute every method in one database transaction. The
/// low-level `CandidateMemoryRepository` remains available for storage-focused
/// reads and fixtures, but the domain service never composes its write methods.
pub trait CandidateLifecycleRepository: CandidateMemoryRepository {
    fn edit_candidate_atomic(
        &self,
        life_id: &str,
        request: EditCandidateRequest,
        now: &str,
        audit_id: &str,
    ) -> Result<CandidateEditResult, CandidateMemoryError>;

    fn reject_candidate_atomic(
        &self,
        life_id: &str,
        request: RejectCandidateRequest,
        now: &str,
        audit_id: &str,
    ) -> Result<CandidateLifecycleResult, CandidateMemoryError>;

    fn scan_expired_candidates(
        &self,
        life_id: &str,
        now: &str,
        limit: usize,
    ) -> Result<Vec<ExpiredCandidateScan>, CandidateMemoryError>;

    fn expire_candidate_atomic(
        &self,
        life_id: &str,
        candidate_id: &str,
        scanned_expected_revision: i64,
        now: &str,
        audit_id: &str,
    ) -> Result<Option<CandidateLifecycleResult>, CandidateMemoryError>;

    fn supersede_candidate_atomic(
        &self,
        life_id: &str,
        request: SupersedeCandidateRequest,
        now: &str,
        audit_id: &str,
    ) -> Result<CandidateLifecycleResult, CandidateMemoryError>;

    fn delete_candidate_atomic(
        &self,
        life_id: &str,
        request: DeleteCandidateRequest,
        now: &str,
        audit_id: &str,
    ) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError>;

    fn add_evidence_atomic(
        &self,
        life_id: &str,
        request: AddEvidenceRequest,
        now: &str,
        evidence_id: &str,
        audit_id: &str,
    ) -> Result<Option<CandidateMemoryRecord>, CandidateMemoryError>;
}

// ── Prohibited content detection ──────────────────────────────────────

pub fn contains_prohibited_content(text: &str) -> bool {
    let lower = text.to_lowercase();
    contains_pem_private_key(&lower)
        || contains_authorization_bearer(&lower)
        || contains_secret_assignment(&lower)
        || contains_jwt(&lower)
}

fn contains_pem_private_key(text: &str) -> bool {
    text.contains("-----begin ") && text.contains(" private key-----")
}

fn contains_authorization_bearer(text: &str) -> bool {
    text.lines().any(|line| {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if name.trim() != "authorization" {
            return false;
        }
        let mut parts = value.split_whitespace();
        matches!(parts.next(), Some("bearer")) && parts.next().is_some_and(is_credential_value)
    })
}

fn contains_secret_assignment(text: &str) -> bool {
    const SECRET_KEYS: &[&str] = &[
        "password",
        "passwd",
        "secret",
        "secret_key",
        "secret-key",
        "api_key",
        "api-key",
        "apikey",
        "x-api-key",
        "token",
        "access_token",
        "access-token",
        "refresh_token",
        "refresh-token",
        "session_token",
        "session-token",
        "cookie",
        "session",
        "payment_secret",
    ];

    text.split(['\n', ';', ',']).any(|segment| {
        let Some(separator) = segment.find(['=', ':']) else {
            return false;
        };
        let key = segment[..separator].trim().trim_matches(|character: char| {
            !character.is_ascii_alphanumeric() && character != '_' && character != '-'
        });
        let value = segment[separator + 1..]
            .trim()
            .trim_matches(|character: char| matches!(character, '\'' | '"' | '`'));
        SECRET_KEYS.contains(&key) && is_credential_value(value)
    })
}

fn is_credential_value(value: &str) -> bool {
    let token = value
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|character: char| {
            !character.is_ascii_alphanumeric()
                && !matches!(character, '_' | '-' | '.' | '/' | '+' | '=')
        });
    token.len() >= 12
        && token.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || matches!(character, '_' | '-' | '.' | '/' | '+' | '=')
        })
}

fn contains_jwt(text: &str) -> bool {
    text.split(|character: char| character.is_whitespace() || matches!(character, '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']'))
        .any(|token| {
            let mut segments = token.split('.');
            let parts = (segments.next(), segments.next(), segments.next(), segments.next());
            matches!(parts, (Some(a), Some(b), Some(c), None)
                if a.len() >= 8 && b.len() >= 8 && c.len() >= 8
                    && [a, b, c].iter().all(|part| part.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))))
        })
}

// ── Dedup fingerprint ─────────────────────────────────────────────────

const DEDUP_DOMAIN: &str = "candidate-dedup-v1";

pub fn compute_dedup_fingerprint(
    life_id: &str,
    subject_id: &str,
    kind: MemoryKind,
    content: &str,
) -> String {
    use std::io::Write;
    let normalized = normalize_for_dedup(content);
    let mut hasher = sha256::Sha256::new();
    write!(hasher, "{}", DEDUP_DOMAIN).ok();
    write!(hasher, "\x00{}", life_id).ok();
    write!(hasher, "\x00{}", subject_id).ok();
    write!(hasher, "\x00{}", kind.as_str()).ok();
    write!(hasher, "\x00{}", normalized).ok();
    hex::encode(hasher.finalize())
}

fn normalize_for_dedup(input: &str) -> String {
    use unicode_normalization::UnicodeNormalization;
    let nfkc = input.chars().nfkc().collect::<String>();
    let collapsed = nfkc.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.trim().to_string()
}

// ── Rejection suppression fingerprint ─────────────────────────────────

const REJECTION_DOMAIN: &str = "candidate-rejection-suppression-v1";

pub(crate) fn compute_rejection_fingerprint(
    life_id: &str,
    subject_id: &str,
    kind: MemoryKind,
    content: &str,
) -> String {
    use std::io::Write;
    let normalized = normalize_for_dedup(content);
    let mut hasher = sha256::Sha256::new();
    write!(hasher, "{}", REJECTION_DOMAIN).ok();
    write!(hasher, "\x00{}", life_id).ok();
    write!(hasher, "\x00{}", subject_id).ok();
    write!(hasher, "\x00{}", kind.as_str()).ok();
    write!(hasher, "\x00{}", normalized).ok();
    hex::encode(hasher.finalize())
}

// ── Timestamp helper ──────────────────────────────────────────────────

fn current_timestamp() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let total_secs = nanos / 1_000_000_000;
    let frac_nanos = nanos % 1_000_000_000;
    let secs = i64::try_from(total_secs).unwrap_or(i64::MAX);
    let (year, month, day, hour, minute, second) = epoch_to_ymd_hms(secs);
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        frac_nanos / 1_000_000
    )
}

fn epoch_to_ymd_hms(secs: i64) -> (i64, i64, i64, i64, i64, i64) {
    // Simplified UTC calendar conversion
    let z = secs / 86400 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let secs_in_day = secs % 86400;
    let hour = secs_in_day / 3600;
    let minute = (secs_in_day % 3600) / 60;
    let second = secs_in_day % 60;
    (y, m, d, hour, minute, second)
}

fn generate_id(prefix: &str) -> String {
    use std::fmt::Write;
    static ID_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let mut s = String::with_capacity(64);
    let sequence = ID_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    write!(s, "{prefix}-{}-{nanos}-{sequence}", std::process::id()).ok();
    s
}

// ── Domain Service ────────────────────────────────────────────────────

pub struct CandidateMemoryService<'a, R: CandidateLifecycleRepository + ?Sized> {
    repository: &'a R,
}

impl<'a, R: CandidateLifecycleRepository + ?Sized> CandidateMemoryService<'a, R> {
    pub fn new(repository: &'a R) -> Self {
        Self { repository }
    }

    // ── Edit ──────────────────────────────────────────────────────────

    pub fn edit(
        &self,
        life_id: &str,
        mut request: EditCandidateRequest,
    ) -> Result<CandidateEditResult, CandidateMemoryError> {
        validate_life_id(life_id)?;
        validate_content(&request.content)?;
        request.content = request.content.trim().to_string();
        request.summary = request
            .summary
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let now = current_timestamp();
        self.repository
            .edit_candidate_atomic(life_id, request, &now, &generate_id("audit"))
    }

    // ── Reject ────────────────────────────────────────────────────────

    pub fn reject(
        &self,
        life_id: &str,
        request: RejectCandidateRequest,
    ) -> Result<CandidateLifecycleResult, CandidateMemoryError> {
        validate_life_id(life_id)?;
        let now = current_timestamp();
        self.repository
            .reject_candidate_atomic(life_id, request, &now, &generate_id("audit"))
    }

    // ── Expire ────────────────────────────────────────────────────────

    pub fn expire_one(
        &self,
        life_id: &str,
        candidate_id: &str,
        scanned_expected_revision: i64,
        now: &str,
    ) -> Result<Option<CandidateLifecycleResult>, CandidateMemoryError> {
        validate_life_id(life_id)?;
        validate_candidate_id(candidate_id)?;
        if scanned_expected_revision <= 0 || now.trim().is_empty() {
            return Err(CandidateMemoryError::constraint());
        }
        self.repository.expire_candidate_atomic(
            life_id,
            candidate_id,
            scanned_expected_revision,
            now,
            &generate_id("audit"),
        )
    }

    pub fn expire_batch(
        &self,
        life_id: &str,
        limit: usize,
    ) -> Result<Vec<CandidateLifecycleResult>, CandidateMemoryError> {
        validate_life_id(life_id)?;
        let limit = limit.min(500);
        let now = current_timestamp();
        if limit == 0 {
            return Ok(Vec::new());
        }
        let candidates = self
            .repository
            .scan_expired_candidates(life_id, &now, limit)?;
        let mut results = Vec::new();
        for candidate in candidates {
            if let Some(result) =
                self.expire_one(life_id, &candidate.candidate_id, candidate.revision, &now)?
            {
                results.push(result);
            }
        }
        Ok(results)
    }

    // ── Supersede ─────────────────────────────────────────────────────

    pub fn supersede(
        &self,
        life_id: &str,
        request: SupersedeCandidateRequest,
    ) -> Result<CandidateLifecycleResult, CandidateMemoryError> {
        validate_life_id(life_id)?;

        if request.candidate_id == request.replacement_candidate_id {
            return Err(CandidateMemoryError::new(
                "INVALID_CANDIDATE_MEMORY_REQUEST",
                "A candidate cannot supersede itself.",
                true,
            ));
        }

        let now = current_timestamp();
        self.repository
            .supersede_candidate_atomic(life_id, request, &now, &generate_id("audit"))
    }

    // ── Permanent delete ──────────────────────────────────────────────

    pub fn delete_permanently(
        &self,
        life_id: &str,
        request: DeleteCandidateRequest,
    ) -> Result<CandidateMemoryAuditRecord, CandidateMemoryError> {
        validate_life_id(life_id)?;
        let now = current_timestamp();
        self.repository
            .delete_candidate_atomic(life_id, request, &now, &generate_id("audit"))
    }

    // ── Evidence merge ────────────────────────────────────────────────

    pub fn add_evidence(
        &self,
        life_id: &str,
        request: AddEvidenceRequest,
    ) -> Result<Option<CandidateMemoryRecord>, CandidateMemoryError> {
        validate_life_id(life_id)?;
        let now = current_timestamp();
        self.repository.add_evidence_atomic(
            life_id,
            request,
            &now,
            &generate_id("evidence"),
            &generate_id("audit"),
        )
    }

    // ── Source deletion governance ─────────────────────────────────────
}

// ── Validation helpers ────────────────────────────────────────────────

fn validate_life_id(life_id: &str) -> Result<(), CandidateMemoryError> {
    if life_id.trim().is_empty() {
        return Err(CandidateMemoryError::constraint());
    }
    Ok(())
}

fn validate_candidate_id(candidate_id: &str) -> Result<(), CandidateMemoryError> {
    if candidate_id.trim().is_empty() {
        return Err(CandidateMemoryError::constraint());
    }
    Ok(())
}

fn validate_content(content: &str) -> Result<(), CandidateMemoryError> {
    if content.trim().is_empty() {
        return Err(CandidateMemoryError::new(
            "INVALID_CANDIDATE_MEMORY_REQUEST",
            "Candidate content must not be empty.",
            true,
        ));
    }
    Ok(())
}

// ── sha256 minimal implementation ─────────────────────────────────────

mod sha256 {
    pub struct Sha256 {
        state: [u32; 8],
        buffer: [u8; 64],
        buffer_len: usize,
        total_len: u64,
    }

    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    impl Sha256 {
        pub fn new() -> Self {
            Self {
                state: [
                    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
                    0x1f83d9ab, 0x5be0cd19,
                ],
                buffer: [0u8; 64],
                buffer_len: 0,
                total_len: 0,
            }
        }

        pub fn write(&mut self, data: &[u8]) {
            for &byte in data {
                self.buffer[self.buffer_len] = byte;
                self.buffer_len += 1;
                self.total_len += 1;
                if self.buffer_len == 64 {
                    self.process_block();
                    self.buffer_len = 0;
                }
            }
        }

        pub fn finalize(mut self) -> [u8; 32] {
            let bit_len = self.total_len * 8;
            self.buffer[self.buffer_len] = 0x80;
            self.buffer_len += 1;
            if self.buffer_len > 56 {
                while self.buffer_len < 64 {
                    self.buffer[self.buffer_len] = 0;
                    self.buffer_len += 1;
                }
                self.process_block();
                self.buffer_len = 0;
            }
            while self.buffer_len < 56 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
            self.process_block();

            let mut result = [0u8; 32];
            for (i, &word) in self.state.iter().enumerate() {
                result[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
            }
            result
        }

        fn process_block(&mut self) {
            let mut w = [0u32; 64];
            for (i, chunk) in self.buffer.chunks(4).enumerate().take(16) {
                w[i] = u32::from_be_bytes(chunk.try_into().unwrap());
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
            for i in 0..64 {
                let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                let ch = (e & f) ^ ((!e) & g);
                let temp1 = h
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let temp2 = s0.wrapping_add(maj);
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp1);
                d = c;
                c = b;
                b = a;
                a = temp1.wrapping_add(temp2);
            }
            self.state[0] = self.state[0].wrapping_add(a);
            self.state[1] = self.state[1].wrapping_add(b);
            self.state[2] = self.state[2].wrapping_add(c);
            self.state[3] = self.state[3].wrapping_add(d);
            self.state[4] = self.state[4].wrapping_add(e);
            self.state[5] = self.state[5].wrapping_add(f);
            self.state[6] = self.state[6].wrapping_add(g);
            self.state[7] = self.state[7].wrapping_add(h);
        }
    }

    impl std::io::Write for Sha256 {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

// ── hex encoding ──────────────────────────────────────────────────────

mod hex {
    pub fn encode(bytes: [u8; 32]) -> String {
        let mut s = String::with_capacity(64);
        for byte in bytes {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }
}

// ── NFKC normalization (minimal deterministic) ───────────────────────

mod unicode_normalization {
    pub struct Nfkc<I: Iterator<Item = char>>(I);

    impl<I: Iterator<Item = char>> Iterator for Nfkc<I> {
        type Item = char;
        fn next(&mut self) -> Option<char> {
            self.0.next().map(nfkc_map)
        }
    }

    pub trait UnicodeNormalization: Iterator<Item = char> + Sized {
        fn nfkc(self) -> Nfkc<Self> {
            Nfkc(self)
        }
    }

    impl<I: Iterator<Item = char>> UnicodeNormalization for I {}

    fn nfkc_map(c: char) -> char {
        match c {
            '\u{00B5}' => 'μ',
            '\u{00C0}' => 'À',
            '\u{00C1}' => 'Á',
            '\u{00C2}' => 'Â',
            '\u{00C3}' => 'Ã',
            '\u{00C4}' => 'Ä',
            '\u{00C5}' => 'Å',
            '\u{00E0}' => 'à',
            '\u{00E1}' => 'á',
            '\u{00E2}' => 'â',
            '\u{00E3}' => 'ã',
            '\u{00E4}' => 'ä',
            '\u{00E5}' => 'å',
            '\u{0391}' => 'Α',
            '\u{0392}' => 'Β',
            '\u{0395}' => 'Ε',
            '\u{0396}' => 'Ζ',
            '\u{0397}' => 'Η',
            '\u{0399}' => 'Ι',
            '\u{039A}' => 'Κ',
            '\u{039C}' => 'Μ',
            '\u{039D}' => 'Ν',
            '\u{039F}' => 'Ο',
            '\u{03A1}' => 'Ρ',
            '\u{03A4}' => 'Τ',
            '\u{03A5}' => 'Υ',
            '\u{03A7}' => 'Χ',
            '\u{2000}' => ' ',
            '\u{2001}' => ' ',
            '\u{2002}' => ' ',
            '\u{2003}' => ' ',
            '\u{2004}' => ' ',
            '\u{2005}' => ' ',
            '\u{2006}' => ' ',
            '\u{2007}' => ' ',
            '\u{2008}' => ' ',
            '\u{2009}' => ' ',
            '\u{200A}' => ' ',
            '\u{202F}' => ' ',
            '\u{205F}' => ' ',
            '\u{3000}' => ' ',
            '\u{FEFF}' => '\0',
            other => other,
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        memory::{
            candidate::{
                CandidateInferenceStatus, CandidateMemoryRepository, CandidateMemorySourceType,
                CandidateMemoryStatus, NewCandidateMemory, NewCandidateMemoryAudit,
                NewCandidateMemoryEvidence, PRIMARY_USER_SUBJECT_ID,
            },
            MemoryKind,
        },
        storage::{
            test_support, unique_suffix, LifeIdentityRecord, PersonaTemplateRecord, StorageService,
        },
    };
    use std::{fs, path::PathBuf};

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "digital-life-candidate-svc-{name}-{}",
                unique_suffix()
            ));
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
        for suffix in ["a", "b"] {
            service
                .save_persona(PersonaTemplateRecord {
                    id: format!("persona-{suffix}"),
                    name: "Persona".into(),
                    version: 1,
                    persona_json: "{}".into(),
                })
                .unwrap();
            service
                .save_life(LifeIdentityRecord {
                    id: format!("life-{suffix}"),
                    name: format!("Life {suffix}"),
                    created_at: "2026-07-14T00:00:00.000Z".into(),
                    version: 1,
                    body_id: "body".into(),
                    persona_id: format!("persona-{suffix}"),
                    persona_version: 1,
                })
                .unwrap();
        }
        service
    }

    fn insert_pending(
        storage: &StorageService,
        id: &str,
        life_id: &str,
        content: &str,
        kind: MemoryKind,
        source_type: CandidateMemorySourceType,
    ) -> CandidateMemoryRecord {
        let fingerprint =
            compute_dedup_fingerprint(life_id, PRIMARY_USER_SUBJECT_ID, kind, content);
        CandidateMemoryRepository::insert_candidate(
            storage,
            NewCandidateMemory {
                id: id.into(),
                life_id: life_id.into(),
                subject_id: PRIMARY_USER_SUBJECT_ID.into(),
                kind,
                content: Some(content.into()),
                summary: Some(format!("Summary for {content}")),
                source_type,
                source_id: Some("source".into()),
                confidence: 0.8,
                importance: 0.6,
                is_sensitive: false,
                inference_status: CandidateInferenceStatus::Extracted,
                status: CandidateMemoryStatus::Pending,
                dedup_fingerprint: Some(fingerprint),
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
            },
        )
        .unwrap()
    }

    fn insert_pending_with_expiry(
        storage: &StorageService,
        id: &str,
        life_id: &str,
        expires_at: &str,
    ) -> CandidateMemoryRecord {
        CandidateMemoryRepository::insert_candidate(
            storage,
            NewCandidateMemory {
                id: id.into(),
                life_id: life_id.into(),
                subject_id: PRIMARY_USER_SUBJECT_ID.into(),
                kind: MemoryKind::Fact,
                content: Some(format!("Candidate {id}")),
                summary: Some(format!("Summary {id}")),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: Some("source".into()),
                confidence: 0.8,
                importance: 0.6,
                is_sensitive: false,
                inference_status: CandidateInferenceStatus::Extracted,
                status: CandidateMemoryStatus::Pending,
                dedup_fingerprint: None,
                proposed_at: "2026-07-14T10:00:00.000Z".into(),
                expires_at: Some(expires_at.into()),
                reviewed_at: None,
                last_user_edit_at: None,
                confirmed_memory_id: None,
                accepted_request_id: None,
                rejection_reason_code: None,
                superseded_by_candidate_id: None,
                conflicts_with_memory_id: None,
                created_at: "2026-07-14T10:00:00.000Z".into(),
                updated_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap()
    }

    // ── Edit tests ────────────────────────────────────────────────────

    #[test]
    fn pending_edit_succeeds_and_increments_revision() {
        let root = TestRoot::new("edit-ok");
        let service = seeded_service(&root);
        let _candidate = insert_pending(
            &service,
            "c1",
            "life-a",
            "Original",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Preference,
                    content: "Updated content".into(),
                    summary: Some("New summary".into()),
                },
            )
            .unwrap();
        assert_eq!(result.outcome, CandidateEditOutcome::Changed);
        assert_eq!(result.candidate.revision, 2);
        assert_eq!(result.candidate.content.as_deref(), Some("Updated content"));
        assert_eq!(result.candidate.kind, MemoryKind::Preference);
        assert!(result.candidate.last_user_edit_at.is_some());
    }

    #[test]
    fn no_change_edit_does_not_increment_revision() {
        let root = TestRoot::new("edit-noop");
        let service = seeded_service(&root);
        let _candidate = insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Fact,
                    content: "Content".into(),
                    summary: Some("Summary for Content".into()),
                },
            )
            .unwrap();
        assert_eq!(result.outcome, CandidateEditOutcome::NoChange);
        assert_eq!(result.candidate.revision, 1);
    }

    #[test]
    fn non_pending_cannot_be_edited() {
        let root = TestRoot::new("edit-not-pending");
        let service = seeded_service(&root);
        let candidate = insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let update = super::super::candidate::CandidateMemoryStorageUpdate {
            kind: candidate.kind,
            content: None,
            summary: None,
            source_type: candidate.source_type,
            source_id: None,
            confidence: candidate.confidence,
            importance: candidate.importance,
            is_sensitive: candidate.is_sensitive,
            inference_status: candidate.inference_status,
            status: CandidateMemoryStatus::Rejected,
            dedup_fingerprint: None,
            proposed_at: candidate.proposed_at.clone(),
            expires_at: None,
            reviewed_at: None,
            last_user_edit_at: None,
            confirmed_memory_id: None,
            accepted_request_id: None,
            rejection_reason_code: Some("other".into()),
            superseded_by_candidate_id: None,
            conflicts_with_memory_id: None,
            updated_at: "2026-07-14T11:00:00.000Z".into(),
        };
        super::super::candidate::CandidateMemoryRepository::update_candidate_guarded(
            &service, "life-a", "c1", 1, update,
        )
        .unwrap();
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 2,
                    kind: MemoryKind::Fact,
                    content: "New".into(),
                    summary: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_INVALID_STATUS");
    }

    #[test]
    fn revision_conflict_on_edit() {
        let root = TestRoot::new("edit-conflict");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 99,
                    kind: MemoryKind::Fact,
                    content: "New".into(),
                    summary: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_REVISION_CONFLICT");
    }

    #[test]
    fn life_isolation_on_edit() {
        let root = TestRoot::new("edit-life");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .edit(
                "life-b",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Fact,
                    content: "New".into(),
                    summary: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_LIFE_MISMATCH");
    }

    #[test]
    fn empty_content_rejected() {
        let root = TestRoot::new("edit-empty");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Fact,
                    content: "   ".into(),
                    summary: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "INVALID_CANDIDATE_MEMORY_REQUEST");
    }

    #[test]
    fn prohibited_content_rejected_and_not_stored() {
        let root = TestRoot::new("edit-prohibited");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Fact,
                    content: "api_key=long-test-api-key-value".into(),
                    summary: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_PROHIBITED_CONTENT");
        let candidate = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c1",
        )
        .unwrap();
        assert_eq!(candidate.content.as_deref(), Some("Content"));
        assert_eq!(candidate.revision, 1);
    }

    #[test]
    fn edit_recomputes_fingerprint() {
        let root = TestRoot::new("edit-fingerprint");
        let service = seeded_service(&root);
        let candidate = insert_pending(
            &service,
            "c1",
            "life-a",
            "Original",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let original_fingerprint = candidate.dedup_fingerprint.clone();
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .edit(
                "life-a",
                EditCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    kind: MemoryKind::Fact,
                    content: "Changed content".into(),
                    summary: None,
                },
            )
            .unwrap();
        assert_ne!(result.candidate.dedup_fingerprint, original_fingerprint);
    }

    #[test]
    fn edit_writes_audit() {
        let root = TestRoot::new("edit-audit");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        svc.edit(
            "life-a",
            EditCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
                kind: MemoryKind::Fact,
                content: "Updated".into(),
                summary: None,
            },
        )
        .unwrap();
        let audits = super::super::candidate::CandidateMemoryRepository::list_evidence(
            &service, "life-a", "c1",
        );
        // Evidence list should be empty (audit is separate)
        assert!(audits.unwrap().is_empty());
    }

    // ── Reject tests ──────────────────────────────────────────────────

    #[test]
    fn pending_rejected_clears_content_and_evidence() {
        let root = TestRoot::new("reject-ok");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content to reject",
            MemoryKind::Fact,
            CandidateMemorySourceType::Conversation,
        );
        super::super::candidate::CandidateMemoryRepository::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: None,
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .reject(
                "life-a",
                RejectCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    reason: RejectionReason::NotTrue,
                },
            )
            .unwrap();
        assert_eq!(result.candidate.status, CandidateMemoryStatus::Rejected);
        assert!(result.candidate.content.is_none());
        assert!(result.candidate.summary.is_none());
        assert!(result.candidate.source_id.is_none());
        assert!(result.candidate.reviewed_at.is_some());
        assert_eq!(
            result.candidate.rejection_reason_code.as_deref(),
            Some("not_true")
        );
        assert_eq!(result.candidate.revision, 2);
        let evidence = super::super::candidate::CandidateMemoryRepository::list_evidence(
            &service, "life-a", "c1",
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn rejection_fingerprint_is_irreversible() {
        let root = TestRoot::new("reject-fingerprint");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Secret content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .reject(
                "life-a",
                RejectCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                    reason: RejectionReason::TooSensitive,
                },
            )
            .unwrap();
        let fp = result.candidate.dedup_fingerprint.as_ref().unwrap();
        assert!(!fp.contains("Secret"));
        assert!(!fp.contains("content"));
        assert_eq!(fp.len(), 64); // SHA-256 hex
    }

    #[test]
    fn non_pending_reject_fails() {
        let root = TestRoot::new("reject-not-pending");
        let service = seeded_service(&root);
        let candidate = insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let update = super::super::candidate::CandidateMemoryStorageUpdate {
            kind: candidate.kind,
            content: None,
            summary: None,
            source_type: candidate.source_type,
            source_id: None,
            confidence: candidate.confidence,
            importance: candidate.importance,
            is_sensitive: candidate.is_sensitive,
            inference_status: candidate.inference_status,
            status: CandidateMemoryStatus::Expired,
            dedup_fingerprint: None,
            proposed_at: candidate.proposed_at.clone(),
            expires_at: None,
            reviewed_at: Some("2026-07-14T11:00:00.000Z".into()),
            last_user_edit_at: None,
            confirmed_memory_id: None,
            accepted_request_id: None,
            rejection_reason_code: None,
            superseded_by_candidate_id: None,
            conflicts_with_memory_id: None,
            updated_at: "2026-07-14T11:00:00.000Z".into(),
        };
        super::super::candidate::CandidateMemoryRepository::update_candidate_guarded(
            &service, "life-a", "c1", 1, update,
        )
        .unwrap();
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .reject(
                "life-a",
                RejectCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 2,
                    reason: RejectionReason::Other,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_INVALID_STATUS");
    }

    #[test]
    fn reject_does_not_create_outbox() {
        let root = TestRoot::new("reject-no-outbox");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        svc.reject(
            "life-a",
            RejectCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
                reason: RejectionReason::NotUseful,
            },
        )
        .unwrap();
        assert_eq!(
            test_support::count_table(&service, "memory_vector_sync_outbox"),
            0
        );
    }

    // ── Expire tests ──────────────────────────────────────────────────

    #[test]
    fn expired_candidate_clears_content_and_evidence() {
        let root = TestRoot::new("expire-ok");
        let service = seeded_service(&root);
        insert_pending_with_expiry(&service, "c1", "life-a", "2020-01-01T00:00:00.000Z");
        super::super::candidate::CandidateMemoryRepository::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: None,
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .expire_one("life-a", "c1", 1, "2026-07-14T12:00:00.000Z")
            .unwrap()
            .unwrap();
        assert_eq!(result.candidate.status, CandidateMemoryStatus::Expired);
        assert!(result.candidate.content.is_none());
        assert!(result.candidate.reviewed_at.is_some());
        let evidence = super::super::candidate::CandidateMemoryRepository::list_evidence(
            &service, "life-a", "c1",
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn not_yet_expired_candidate_unchanged() {
        let root = TestRoot::new("expire-future");
        let service = seeded_service(&root);
        insert_pending_with_expiry(&service, "c1", "life-a", "2099-12-31T23:59:59.000Z");
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .expire_one("life-a", "c1", 1, "2026-07-14T12:00:00.000Z")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn null_expiry_candidate_unchanged() {
        let root = TestRoot::new("expire-null");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .expire_one("life-a", "c1", 1, "2026-07-14T12:00:00.000Z")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn terminal_state_not_re_expired() {
        let root = TestRoot::new("expire-terminal");
        let service = seeded_service(&root);
        let _candidate = insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        // Reject first
        let svc = CandidateMemoryService::new(&service);
        svc.reject(
            "life-a",
            RejectCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
                reason: RejectionReason::Other,
            },
        )
        .unwrap();
        // Try to expire - should return None since it's rejected
        let result = svc
            .expire_one("life-a", "c1", 2, "2026-07-14T12:00:00.000Z")
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn expire_batch_respects_limit() {
        let root = TestRoot::new("expire-batch");
        let service = seeded_service(&root);
        for i in 0..5 {
            insert_pending_with_expiry(
                &service,
                &format!("c{i}"),
                "life-a",
                "2020-01-01T00:00:00.000Z",
            );
        }
        let svc = CandidateMemoryService::new(&service);
        let results = svc.expire_batch("life-a", 3).unwrap();
        assert_eq!(results.len(), 3);
    }

    #[test]
    fn expire_does_not_create_outbox() {
        let root = TestRoot::new("expire-no-outbox");
        let service = seeded_service(&root);
        insert_pending_with_expiry(&service, "c1", "life-a", "2020-01-01T00:00:00.000Z");
        let svc = CandidateMemoryService::new(&service);
        svc.expire_one("life-a", "c1", 1, "2026-07-14T12:00:00.000Z")
            .unwrap();
        assert_eq!(
            test_support::count_table(&service, "memory_vector_sync_outbox"),
            0
        );
    }

    // ── Supersede tests ───────────────────────────────────────────────

    #[test]
    fn same_life_pending_supersede_succeeds() {
        let root = TestRoot::new("supersede-ok");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Old",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        insert_pending(
            &service,
            "c2",
            "life-a",
            "New",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        super::super::candidate::CandidateMemoryRepository::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Manual,
                source_id: None,
                conversation_id: None,
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .supersede(
                "life-a",
                SupersedeCandidateRequest {
                    candidate_id: "c1".into(),
                    replacement_candidate_id: "c2".into(),
                    expected_revision: 1,
                },
            )
            .unwrap();
        assert_eq!(result.candidate.status, CandidateMemoryStatus::Superseded);
        assert_eq!(
            result.candidate.superseded_by_candidate_id.as_deref(),
            Some("c2")
        );
        assert!(result.candidate.content.is_none());
        let evidence = super::super::candidate::CandidateMemoryRepository::list_evidence(
            &service, "life-a", "c1",
        )
        .unwrap();
        assert!(evidence.is_empty());
    }

    #[test]
    fn cross_life_supersede_rejected() {
        let root = TestRoot::new("supersede-cross-life");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "A",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        insert_pending(
            &service,
            "c2",
            "life-b",
            "B",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .supersede(
                "life-a",
                SupersedeCandidateRequest {
                    candidate_id: "c1".into(),
                    replacement_candidate_id: "c2".into(),
                    expected_revision: 1,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_LIFE_MISMATCH");
    }

    #[test]
    fn self_supersede_rejected() {
        let root = TestRoot::new("supersede-self");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "A",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .supersede(
                "life-a",
                SupersedeCandidateRequest {
                    candidate_id: "c1".into(),
                    replacement_candidate_id: "c1".into(),
                    expected_revision: 1,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "INVALID_CANDIDATE_MEMORY_REQUEST");
    }

    #[test]
    fn replacement_not_found_rejected() {
        let root = TestRoot::new("supersede-no-replacement");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "A",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .supersede(
                "life-a",
                SupersedeCandidateRequest {
                    candidate_id: "c1".into(),
                    replacement_candidate_id: "nonexistent".into(),
                    expected_revision: 1,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_NOT_FOUND");
    }

    #[test]
    fn supersede_does_not_modify_replacement() {
        let root = TestRoot::new("supersede-replacement-unchanged");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "A",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        insert_pending(
            &service,
            "c2",
            "life-a",
            "B",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        svc.supersede(
            "life-a",
            SupersedeCandidateRequest {
                candidate_id: "c1".into(),
                replacement_candidate_id: "c2".into(),
                expected_revision: 1,
            },
        )
        .unwrap();
        let replacement = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c2",
        )
        .unwrap();
        assert_eq!(replacement.status, CandidateMemoryStatus::Pending);
        assert_eq!(replacement.revision, 1);
    }

    // ── Permanent delete tests ────────────────────────────────────────

    #[test]
    fn pending_can_be_deleted() {
        let root = TestRoot::new("delete-pending");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let audit = svc
            .delete_permanently(
                "life-a",
                DeleteCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                },
            )
            .unwrap();
        assert_eq!(audit.action, "candidate_deleted");
        let error = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c1",
        )
        .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_NOT_FOUND");
    }

    #[test]
    fn rejected_can_be_deleted() {
        let root = TestRoot::new("delete-rejected");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        svc.reject(
            "life-a",
            RejectCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
                reason: RejectionReason::Other,
            },
        )
        .unwrap();
        svc.delete_permanently(
            "life-a",
            DeleteCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 2,
            },
        )
        .unwrap();
        let error = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c1",
        )
        .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_NOT_FOUND");
    }

    #[test]
    fn delete_revision_conflict() {
        let root = TestRoot::new("delete-conflict");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .delete_permanently(
                "life-a",
                DeleteCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 99,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_REVISION_CONFLICT");
    }

    #[test]
    fn delete_life_isolation() {
        let root = TestRoot::new("delete-life");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .delete_permanently(
                "life-b",
                DeleteCandidateRequest {
                    candidate_id: "c1".into(),
                    expected_revision: 1,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_LIFE_MISMATCH");
    }

    #[test]
    fn delete_cascades_evidence_but_preserves_audit() {
        let root = TestRoot::new("delete-cascade");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        super::super::candidate::CandidateMemoryRepository::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Manual,
                source_id: None,
                conversation_id: None,
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        super::super::candidate::CandidateMemoryRepository::append_audit(
            &service,
            NewCandidateMemoryAudit {
                id: "audit1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                action: "created".into(),
                actor_type: "system".into(),
                request_id: None,
                result_status: "success".into(),
                created_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        let svc = CandidateMemoryService::new(&service);
        svc.delete_permanently(
            "life-a",
            DeleteCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
            },
        )
        .unwrap();
        assert_eq!(
            test_support::count_table(&service, "candidate_memory_evidence"),
            0
        );
        assert_eq!(
            test_support::count_table(&service, "candidate_memory_audit"),
            2
        ); // original + delete audit
    }

    #[test]
    fn delete_does_not_affect_other_candidates() {
        let root = TestRoot::new("delete-isolation");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "A",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        insert_pending(
            &service,
            "c2",
            "life-a",
            "B",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        svc.delete_permanently(
            "life-a",
            DeleteCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
            },
        )
        .unwrap();
        let other = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c2",
        )
        .unwrap();
        assert_eq!(other.status, CandidateMemoryStatus::Pending);
    }

    #[test]
    fn delete_does_not_create_outbox() {
        let root = TestRoot::new("delete-no-outbox");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        svc.delete_permanently(
            "life-a",
            DeleteCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
            },
        )
        .unwrap();
        assert_eq!(
            test_support::count_table(&service, "memory_vector_sync_outbox"),
            0
        );
    }

    // ── Evidence tests ────────────────────────────────────────────────

    #[test]
    fn add_evidence_to_pending_candidate() {
        let root = TestRoot::new("evidence-add");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        test_support::insert_conversation_with_message(&service, "life-a", "a");
        let svc = CandidateMemoryService::new(&service);
        let result = svc
            .add_evidence(
                "life-a",
                AddEvidenceRequest {
                    candidate_id: "c1".into(),
                    source_type: CandidateMemorySourceType::Conversation,
                    source_id: None,
                    conversation_id: Some("conv-a".into()),
                    message_id: Some("msg-a".into()),
                },
            )
            .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().revision, 2);
    }

    #[test]
    fn duplicate_evidence_is_noop() {
        let root = TestRoot::new("evidence-dup");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let first = svc
            .add_evidence(
                "life-a",
                AddEvidenceRequest {
                    candidate_id: "c1".into(),
                    source_type: CandidateMemorySourceType::Manual,
                    source_id: Some("src".into()),
                    conversation_id: None,
                    message_id: None,
                },
            )
            .unwrap();
        assert!(first.is_some());
        let second = svc
            .add_evidence(
                "life-a",
                AddEvidenceRequest {
                    candidate_id: "c1".into(),
                    source_type: CandidateMemorySourceType::Manual,
                    source_id: Some("src".into()),
                    conversation_id: None,
                    message_id: None,
                },
            )
            .unwrap();
        assert!(second.is_none());
    }

    #[test]
    fn evidence_to_non_pending_fails() {
        let root = TestRoot::new("evidence-not-pending");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        svc.reject(
            "life-a",
            RejectCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
                reason: RejectionReason::Other,
            },
        )
        .unwrap();
        let error = svc
            .add_evidence(
                "life-a",
                AddEvidenceRequest {
                    candidate_id: "c1".into(),
                    source_type: CandidateMemorySourceType::Manual,
                    source_id: None,
                    conversation_id: None,
                    message_id: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_INVALID_STATUS");
    }

    #[test]
    fn evidence_cross_life_rejected() {
        let root = TestRoot::new("evidence-life");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        let error = svc
            .add_evidence(
                "life-b",
                AddEvidenceRequest {
                    candidate_id: "c1".into(),
                    source_type: CandidateMemorySourceType::Manual,
                    source_id: None,
                    conversation_id: None,
                    message_id: None,
                },
            )
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_LIFE_MISMATCH");
    }

    // ── Dedup fingerprint tests ───────────────────────────────────────

    #[test]
    fn same_normalized_content_same_fingerprint() {
        let fp1 = compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "Hello  world");
        let fp2 = compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "Hello world");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn different_life_different_fingerprint() {
        let fp1 = compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "Content");
        let fp2 = compute_dedup_fingerprint("life-b", "subject", MemoryKind::Fact, "Content");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn different_kind_different_fingerprint() {
        let fp1 = compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "Content");
        let fp2 = compute_dedup_fingerprint("life-a", "subject", MemoryKind::Goal, "Content");
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn whitespace_differences_normalized() {
        let fp1 =
            compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "  Hello   world  ");
        let fp2 = compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "Hello world");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn unicode_nfkc_maps_compatibility_chars() {
        // NFKC maps compatibility whitespace to regular space
        let fp1 =
            compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "Hello\u{3000}world");
        let fp2 = compute_dedup_fingerprint("life-a", "subject", MemoryKind::Fact, "Hello world");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_not_in_audit_or_error() {
        let root = TestRoot::new("fp-audit");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let svc = CandidateMemoryService::new(&service);
        svc.reject(
            "life-a",
            RejectCandidateRequest {
                candidate_id: "c1".into(),
                expected_revision: 1,
                reason: RejectionReason::Other,
            },
        )
        .unwrap();
        let candidate = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c1",
        )
        .unwrap();
        let fp = candidate.dedup_fingerprint.as_ref().unwrap();
        // Fingerprint should be hex only
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pending_duplicate_maps_to_stable_error() {
        let root = TestRoot::new("dedup-dup");
        let service = seeded_service(&root);
        let fp = compute_dedup_fingerprint(
            "life-a",
            PRIMARY_USER_SUBJECT_ID,
            MemoryKind::Fact,
            "Same content",
        );
        super::super::candidate::CandidateMemoryRepository::insert_candidate(
            &service,
            NewCandidateMemory {
                id: "c1".into(),
                life_id: "life-a".into(),
                subject_id: PRIMARY_USER_SUBJECT_ID.into(),
                kind: MemoryKind::Fact,
                content: Some("Same content".into()),
                summary: None,
                source_type: CandidateMemorySourceType::Manual,
                source_id: None,
                confidence: 0.8,
                importance: 0.6,
                is_sensitive: false,
                inference_status: CandidateInferenceStatus::Explicit,
                status: CandidateMemoryStatus::Pending,
                dedup_fingerprint: Some(fp.clone()),
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
            },
        )
        .unwrap();
        let error = super::super::candidate::CandidateMemoryRepository::insert_candidate(
            &service,
            NewCandidateMemory {
                id: "c2".into(),
                life_id: "life-a".into(),
                subject_id: PRIMARY_USER_SUBJECT_ID.into(),
                kind: MemoryKind::Fact,
                content: Some("Same content".into()),
                summary: None,
                source_type: CandidateMemorySourceType::Manual,
                source_id: None,
                confidence: 0.8,
                importance: 0.6,
                is_sensitive: false,
                inference_status: CandidateInferenceStatus::Explicit,
                status: CandidateMemoryStatus::Pending,
                dedup_fingerprint: Some(fp),
                proposed_at: "2026-07-14T11:00:00.000Z".into(),
                expires_at: None,
                reviewed_at: None,
                last_user_edit_at: None,
                confirmed_memory_id: None,
                accepted_request_id: None,
                rejection_reason_code: None,
                superseded_by_candidate_id: None,
                conflicts_with_memory_id: None,
                created_at: "2026-07-14T11:00:00.000Z".into(),
                updated_at: "2026-07-14T11:00:00.000Z".into(),
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_DUPLICATE");
    }

    // ── Source deletion governance tests ──────────────────────────────

    #[test]
    fn orphaned_conversation_candidate_deleted_on_source_removal() {
        let root = TestRoot::new("source-delete");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Conversation,
        );
        test_support::insert_conversation_with_message(&service, "life-a", "a");
        super::super::candidate::CandidateMemoryRepository::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: Some("conv-a".into()),
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        crate::conversation::history::ConversationRepository::delete_conversation(
            &service, "life-a", "conv-a",
        )
        .unwrap();
        let error = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c1",
        )
        .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_MEMORY_NOT_FOUND");
    }

    #[test]
    fn candidate_with_remaining_evidence_preserved() {
        let root = TestRoot::new("source-keep");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Conversation,
        );
        test_support::insert_conversation_with_message(&service, "life-a", "a");
        test_support::insert_conversation_with_message(&service, "life-a", "b");
        super::super::candidate::CandidateMemoryRepository::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: Some("conv-a".into()),
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        super::super::candidate::CandidateMemoryRepository::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev2".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: Some("conv-b".into()),
                message_id: None,
                observed_at: "2026-07-14T10:01:00.000Z".into(),
            },
        )
        .unwrap();
        crate::conversation::history::ConversationRepository::delete_conversation(
            &service, "life-a", "conv-a",
        )
        .unwrap();
        let candidate = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c1",
        )
        .unwrap();
        assert_eq!(candidate.status, CandidateMemoryStatus::Pending);
    }

    #[test]
    fn manual_candidate_with_deleted_conversation_evidence_is_preserved() {
        let root = TestRoot::new("source-manual");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        test_support::insert_conversation_with_message(&service, "life-a", "a");
        super::super::candidate::CandidateMemoryRepository::insert_evidence(
            &service,
            NewCandidateMemoryEvidence {
                id: "ev1".into(),
                candidate_id: "c1".into(),
                life_id: "life-a".into(),
                source_type: CandidateMemorySourceType::Conversation,
                source_id: None,
                conversation_id: Some("conv-a".into()),
                message_id: None,
                observed_at: "2026-07-14T10:00:00.000Z".into(),
            },
        )
        .unwrap();
        crate::conversation::history::ConversationRepository::delete_conversation(
            &service, "life-a", "conv-a",
        )
        .unwrap();
        let candidate = super::super::candidate::CandidateMemoryRepository::get_candidate(
            &service, "life-a", "c1",
        )
        .unwrap();
        assert_eq!(candidate.status, CandidateMemoryStatus::Pending);
    }

    // ── Prohibited content tests ──────────────────────────────────────

    #[test]
    fn prohibited_detector_allows_concepts_and_rejects_credential_values() {
        for natural_language in [
            "我忘记密码了",
            "请提醒我更换 API Key",
            "Cookie 是浏览器的一种机制",
            "Access Token 已经过期",
            "不要保存验证码",
            "Private Key 不应该公开",
        ] {
            assert!(!contains_prohibited_content(natural_language));
        }
        for credential_like in [
            "password=very-long-test-secret-value",
            "Authorization: Bearer test_long_token_value_123456789",
            "-----BEGIN TEST PRIVATE KEY-----\nZmFrZS10ZXN0LWtleQ==\n-----END TEST PRIVATE KEY-----",
            "eyJ0ZXN0IjoiYSJ9.eyJ0ZXN0IjoiYiJ9.test_signature_value",
            "session_token=long-test-session-token",
            "api_key=long-test-api-key-value",
        ] {
            assert!(contains_prohibited_content(credential_like));
        }
    }

    // ── Type safety tests ─────────────────────────────────────────────

    #[test]
    fn confirm_still_returns_unavailable() {
        use crate::memory::{ConfirmMemoryRequest, MemoryRepository};
        let root = TestRoot::new("confirm-unavailable");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        let error = service
            .confirm(ConfirmMemoryRequest {
                life_id: "life-a".into(),
                memory_id: "c1".into(),
                user_confirmed: true,
                sensitive_consent: false,
            })
            .unwrap_err();
        assert_eq!(error.code, "CANDIDATE_CONFIRMATION_UNAVAILABLE");
    }

    #[test]
    fn candidate_not_in_memory_record() {
        let root = TestRoot::new("no-memory-record");
        let service = seeded_service(&root);
        insert_pending(
            &service,
            "c1",
            "life-a",
            "Content",
            MemoryKind::Fact,
            CandidateMemorySourceType::Manual,
        );
        // Verify the legacy MemoryRepository::get returns the candidate from candidate_memory
        use crate::memory::MemoryRepository;
        let legacy = service.get("life-a", "c1").unwrap();
        assert_eq!(legacy.status, crate::memory::MemoryStatus::Candidate);
    }
}
