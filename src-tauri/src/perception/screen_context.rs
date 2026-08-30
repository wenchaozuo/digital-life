//! D24-A ephemeral screen-context handoff authority foundation.
//!
//! [`ScreenContextHandoffBroker`] owns exactly one canonical process-local
//! handoff state.  A later D24 batch installs a successfully produced D23
//! [`ScreenObservation`] as a bounded `Candidate`; the broker can then issue a
//! single `Grant` that a governed conversation request may bind once
//! (`conversation_id` + `request_id`) and claim while it stays valid.
//!
//! Frozen contract:
//!
//! - one canonical state only: `EMPTY`, `CANDIDATE`, `GRANT_PENDING`,
//!   `GRANT_BOUND` — no observation history, no queue, no per-Life map, no
//!   multiple active grants;
//! - the candidate retains only bounded ScreenObservation-derived content
//!   (captured timestamp, Recognized/NoText status, bounded text, truncated
//!   flag) plus backend lifecycle metadata; it never contains a raw frame,
//!   raw pixel data, a native capture item, a native window handle, a process
//!   identity, a window title, a monitor identity, OCR geometry, or OCR
//!   native objects;
//! - the 10-minute handoff TTL starts when the candidate is installed, is
//!   measured with monotonic [`std::time::Instant`], is lazy (no background
//!   timer), and is never refreshed by grant issuance or claiming;
//! - installing a new candidate atomically replaces ANY previous state
//!   (candidate, pending grant, or bound grant) and therefore revokes the old
//!   handoff authority;
//! - grant issuance is a one-way MOVE of the payload; the original candidate
//!   identity becomes unusable;
//! - a grant binds exactly once; the identical same-request tuple may claim
//!   the identical immutable payload again (same-request retry), while any
//!   different Life / session fence / conversation / request fails closed;
//! - claiming never consumes the payload: only replacement, cancellation,
//!   expiry, or retirement removes the authority;
//! - cancellation clears any current state; retirement clears only a bound
//!   grant whose binding matches the expected scope;
//! - no Candidate or Grant survives broker reconstruction; a freshly
//!   constructed broker is always `EMPTY` and nothing is persisted;
//! - every state transition is guarded by one canonical mutex; authority-
//!   broadening operations fail closed on a poisoned lock, and
//!   authority-shrinking operations may recover only toward `EMPTY`.
//!
//! The broker performs no screen capture and no OCR, adds no WebView
//! commands, changes no Chat ACL, and reads no database.  The stored D23
//! session fence is only stale-session evidence: it never substitutes for the
//! durable screen-perception policy authorization, and D24-D performs the
//! final durable-policy reread before any Provider use.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use super::screen_ocr::{ScreenObservation, ScreenObservationStatus};

/// Maximum handoff lifetime in minutes, measured from candidate installation
/// with monotonic time.  Frozen: 10 minutes, never refreshed.
pub(crate) const SCREEN_CONTEXT_HANDOFF_TTL: Duration = Duration::from_secs(10 * 60);

/// Byte bound for a handoff candidate's retained text.  It must never exceed
/// the frozen D23 observation bound and there must be no larger alternate text
/// representation.
pub(crate) const SCREEN_CONTEXT_MAX_TEXT_BYTES: usize = 32 * 1024;

/// Line bound for a handoff candidate's retained text.  It must never exceed
/// the frozen D23 observation bound.
pub(crate) const SCREEN_CONTEXT_MAX_LINES: usize = 256;

/// Hex length of a generated opaque identity (candidate or grant).
const IDENTITY_HEX_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenContextErrorCode {
    InvalidArgument,
    NoCurrentContext,
    Expired,
    LifeMismatch,
    SessionFenceMismatch,
    NoUsableScreenContext,
    GrantAlreadyBound,
    SynchronizationUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenContextError {
    pub(crate) code: ScreenContextErrorCode,
    pub(crate) message: String,
}

impl ScreenContextError {
    fn new(code: ScreenContextErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(ScreenContextErrorCode::InvalidArgument, message)
    }

    pub(crate) fn no_current_context() -> Self {
        Self::new(
            ScreenContextErrorCode::NoCurrentContext,
            "No current screen context handoff exists.",
        )
    }

    pub(crate) fn expired() -> Self {
        Self::new(
            ScreenContextErrorCode::Expired,
            "The screen context handoff has expired.",
        )
    }

    pub(crate) fn life_mismatch() -> Self {
        Self::new(
            ScreenContextErrorCode::LifeMismatch,
            "The screen context handoff belongs to a different Life.",
        )
    }

    pub(crate) fn session_fence_mismatch() -> Self {
        Self::new(
            ScreenContextErrorCode::SessionFenceMismatch,
            "The supplied D23 session fence does not match the handoff fence.",
        )
    }

    pub(crate) fn no_usable_screen_context() -> Self {
        Self::new(
            ScreenContextErrorCode::NoUsableScreenContext,
            "The current screen observation contains no usable screen text.",
        )
    }

    pub(crate) fn grant_already_bound() -> Self {
        Self::new(
            ScreenContextErrorCode::GrantAlreadyBound,
            "The grant is already bound to a different request scope.",
        )
    }

    pub(crate) fn synchronization_unavailable() -> Self {
        Self::new(
            ScreenContextErrorCode::SynchronizationUnavailable,
            "The screen context handoff authority is temporarily unavailable.",
        )
    }
}

/// The D23 session fence as captured by the later integration layer.  It is
/// opaque process-local evidence; the broker only compares it for exact
/// equality and never interprets it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenContextSessionFence(pub(crate) u64);

/// Status of the retained, bounded observation text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenContextTextStatus {
    Recognized,
    NoText,
}

/// Immutable, bounded perception context returned to a bound claim.  This is
/// the only payload that can leave the broker.  The type deliberately contains
/// no raw frame, raw pixel data, native capture item, native window handle,
/// process identity, window title, monitor identity, OCR geometry, or OCR
/// native objects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenContextPayload {
    pub(crate) captured_at: String,
    pub(crate) status: ScreenContextTextStatus,
    pub(crate) text: String,
    pub(crate) truncated: bool,
}

/// Validated, non-empty identifier arguments for broker operations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenContextIds {
    pub(crate) life_id: String,
    pub(crate) session_fence: ScreenContextSessionFence,
    pub(crate) conversation_id: String,
    pub(crate) request_id: String,
}

/// Inputs for installing a candidate from a successfully produced D23
/// observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenContextCandidateInput {
    pub(crate) life_id: String,
    pub(crate) session_fence: ScreenContextSessionFence,
    pub(crate) observation: ScreenObservation,
}

/// Monotonic clock seam owned by the broker instance.  Production uses
/// [`std::time::Instant`]; tests install a per-instance deterministic clock.
/// There is deliberately no process-global test clock.
trait BrokerClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct InstantBrokerClock;

impl BrokerClock for InstantBrokerClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScreenContextState {
    Empty,
    Candidate {
        candidate_id: String,
        life_id: String,
        session_fence: ScreenContextSessionFence,
        payload: ScreenContextPayload,
        created_at: Instant,
        deadline: Instant,
    },
    GrantPending {
        grant_id: String,
        life_id: String,
        session_fence: ScreenContextSessionFence,
        payload: ScreenContextPayload,
        deadline: Instant,
    },
    GrantBound {
        grant_id: String,
        life_id: String,
        session_fence: ScreenContextSessionFence,
        payload: ScreenContextPayload,
        deadline: Instant,
        conversation_id: String,
        request_id: String,
    },
}

/// The single canonical process-local screen-context handoff authority.
///
/// Every state transition runs through one [`Mutex`].  A freshly constructed
/// broker is always `EMPTY`; no state survives reconstruction and nothing is
/// persisted.  The broker never captures the screen and never performs OCR.
pub(crate) struct ScreenContextHandoffBroker {
    state: Mutex<ScreenContextState>,
    clock: Box<dyn BrokerClock>,
}

impl ScreenContextHandoffBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(ScreenContextState::Empty),
            clock: Box::new(InstantBrokerClock),
        }
    }

    #[cfg(test)]
    fn with_clock(clock: Box<dyn BrokerClock>) -> Self {
        Self {
            state: Mutex::new(ScreenContextState::Empty),
            clock,
        }
    }

    /// Installs a new candidate from a successfully produced D23
    /// [`ScreenObservation`].  The installation atomically replaces ANY
    /// previous broker state — previous Candidate, previous Pending Grant, or
    /// previous Bound Grant — which revokes the old handoff authority.  The
    /// 10-minute TTL starts here, at monotonic candidate creation, and is
    /// never reset by later operations.
    pub(crate) fn install_candidate(
        &self,
        input: ScreenContextCandidateInput,
    ) -> Result<String, ScreenContextError> {
        let ScreenContextCandidateInput {
            life_id,
            session_fence,
            observation,
        } = input;
        validate_life_id(&life_id)?;
        let payload = bounded_payload(observation)?;
        let candidate_id = generate_opaque_identity()?;
        let now = self.clock.now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ScreenContextError::synchronization_unavailable())?;
        *state = ScreenContextState::Candidate {
            candidate_id: candidate_id.clone(),
            life_id,
            session_fence,
            payload,
            created_at: now,
            deadline: now + SCREEN_CONTEXT_HANDOFF_TTL,
        };
        Ok(candidate_id)
    }

    /// Atomically issues a grant for the current candidate.  All six frozen
    /// checks must pass: current state is Candidate, the candidate ID matches,
    /// the candidate is not expired, the Life matches, the supplied D23
    /// session fence equals the candidate's stored fence, and the observation
    /// status is usable.  A `NoText` candidate MUST fail with
    /// [`ScreenContextErrorCode::NoUsableScreenContext`]; no empty grant is
    /// ever fabricated.
    ///
    /// On success the payload is MOVED into a new `GRANT_PENDING` state with a
    /// fresh opaque grant identity; the candidate identity becomes unusable
    /// and the original candidate deadline is retained.
    pub(crate) fn issue_grant(
        &self,
        candidate_id: &str,
        life_id: &str,
        current_session_fence: ScreenContextSessionFence,
    ) -> Result<String, ScreenContextError> {
        validate_life_id(life_id)?;
        let grant_id = generate_opaque_identity()?;
        let now = self.clock.now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ScreenContextError::synchronization_unavailable())?;
        match &mut *state {
            ScreenContextState::Candidate {
                candidate_id: stored_candidate_id,
                life_id: candidate_life_id,
                session_fence: candidate_fence,
                payload,
                deadline,
                ..
            } => {
                if candidate_id != *stored_candidate_id {
                    return Err(ScreenContextError::no_current_context());
                }
                if now >= *deadline {
                    return Err(ScreenContextError::expired());
                }
                if life_id != *candidate_life_id {
                    return Err(ScreenContextError::life_mismatch());
                }
                if current_session_fence != *candidate_fence {
                    return Err(ScreenContextError::session_fence_mismatch());
                }
                if payload.status != ScreenContextTextStatus::Recognized {
                    return Err(ScreenContextError::no_usable_screen_context());
                }
                *state = ScreenContextState::GrantPending {
                    grant_id: grant_id.clone(),
                    life_id: life_id.to_string(),
                    session_fence: *candidate_fence,
                    payload: payload.clone(),
                    deadline: *deadline,
                };
                Ok(grant_id)
            }
            _ => Err(ScreenContextError::no_current_context()),
        }
    }

    /// Atomically binds a Pending Grant to exactly one request scope and
    /// returns the immutable, bounded perception context.  The first valid
    /// claim transitions `GRANT_PENDING → GRANT_BOUND`; the exact same tuple
    /// may claim the identical payload again while the grant remains valid
    /// (same-request retry), and any different Life / session fence /
    /// conversation / request fails closed.  Claiming never consumes or
    /// mutates the payload.
    pub(crate) fn claim_grant(
        &self,
        ids: ScreenContextIds,
    ) -> Result<ScreenContextPayload, ScreenContextError> {
        let ScreenContextIds {
            life_id,
            session_fence,
            conversation_id,
            request_id,
        } = ids;
        validate_life_id(&life_id)?;
        validate_scope_id("conversation identity", &conversation_id)?;
        validate_scope_id("request identity", &request_id)?;
        let now = self.clock.now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ScreenContextError::synchronization_unavailable())?;
        match &mut *state {
            ScreenContextState::GrantPending {
                grant_id,
                life_id: grant_life_id,
                session_fence: grant_fence,
                payload,
                deadline,
            } => {
                if now >= *deadline {
                    return Err(ScreenContextError::expired());
                }
                if life_id != *grant_life_id {
                    return Err(ScreenContextError::life_mismatch());
                }
                if session_fence != *grant_fence {
                    return Err(ScreenContextError::session_fence_mismatch());
                }
                let bound_payload = payload.clone();
                *state = ScreenContextState::GrantBound {
                    grant_id: grant_id.clone(),
                    life_id: life_id.clone(),
                    session_fence: *grant_fence,
                    payload: bound_payload.clone(),
                    deadline: *deadline,
                    conversation_id: conversation_id.clone(),
                    request_id: request_id.clone(),
                };
                Ok(bound_payload)
            }
            ScreenContextState::GrantBound {
                grant_id: _,
                life_id: grant_life_id,
                session_fence: grant_fence,
                payload,
                deadline,
                conversation_id: bound_conversation_id,
                request_id: bound_request_id,
            } => {
                if now >= *deadline {
                    return Err(ScreenContextError::expired());
                }
                if life_id != *grant_life_id {
                    return Err(ScreenContextError::life_mismatch());
                }
                if session_fence != *grant_fence {
                    return Err(ScreenContextError::session_fence_mismatch());
                }
                if conversation_id != *bound_conversation_id || request_id != *bound_request_id {
                    return Err(ScreenContextError::grant_already_bound());
                }
                Ok(payload.clone())
            }
            _ => Err(ScreenContextError::no_current_context()),
        }
    }

    /// Clears whatever current state exists — Candidate, Pending Grant, or
    /// Bound Grant — back to `EMPTY`.  Cancellation only shrinks authority:
    /// no previous ID may become valid again.  As an authority-shrinking
    /// operation, a poisoned lock may recover only toward `EMPTY`.
    pub(crate) fn cancel(&self) -> Result<(), ScreenContextError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ScreenContextError::synchronization_unavailable())?;
        *state = ScreenContextState::Empty;
        Ok(())
    }

    /// Retires a Bound Grant after a successful governed conversation commit.
    /// The expected bound identity/scope must match exactly; a mismatched
    /// retirement scope must not destroy another authority.  Expiry is also
    /// checked: an expired grant is already dead and cannot be retired.  On
    /// valid retirement the state becomes `EMPTY`.
    pub(crate) fn retire_bound_grant(
        &self,
        grant_id: &str,
        life_id: &str,
        conversation_id: &str,
        request_id: &str,
    ) -> Result<(), ScreenContextError> {
        validate_life_id(life_id)?;
        validate_scope_id("conversation identity", conversation_id)?;
        validate_scope_id("request identity", request_id)?;
        let now = self.clock.now();
        let mut state = self
            .state
            .lock()
            .map_err(|_| ScreenContextError::synchronization_unavailable())?;
        match &mut *state {
            ScreenContextState::GrantBound {
                grant_id: bound_grant_id,
                life_id: bound_life_id,
                session_fence: _,
                payload: _,
                deadline,
                conversation_id: bound_conversation_id,
                request_id: bound_request_id,
            } => {
                if now >= *deadline {
                    return Err(ScreenContextError::expired());
                }
                if grant_id != *bound_grant_id
                    || life_id != *bound_life_id
                    || conversation_id != *bound_conversation_id
                    || request_id != *bound_request_id
                {
                    return Err(ScreenContextError::grant_already_bound());
                }
                *state = ScreenContextState::Empty;
                Ok(())
            }
            _ => Err(ScreenContextError::no_current_context()),
        }
    }
}

fn validate_life_id(life_id: &str) -> Result<(), ScreenContextError> {
    if life_id.trim().is_empty() {
        return Err(ScreenContextError::invalid_argument(
            "life identity must not be empty.",
        ));
    }
    Ok(())
}

fn validate_scope_id(name: &str, value: &str) -> Result<(), ScreenContextError> {
    if value.trim().is_empty() {
        return Err(ScreenContextError::invalid_argument(format!(
            "{name} must not be empty."
        )));
    }
    Ok(())
}

/// Converts a D23 [`ScreenObservation`] into the bounded handoff payload,
/// applying the frozen D23 bounds (32 KiB text / 256 lines) independently of
/// the observation's own truncation flag.  The candidate may only retain the
/// bounded ScreenObservation-derived content; it must never carry the raw
/// observation or any frame/native target material.
fn bounded_payload(
    observation: ScreenObservation,
) -> Result<ScreenContextPayload, ScreenContextError> {
    let status = match observation.status {
        ScreenObservationStatus::Recognized => ScreenContextTextStatus::Recognized,
        ScreenObservationStatus::NoText => ScreenContextTextStatus::NoText,
    };
    let mut text = observation.text;
    let mut truncated = observation.truncated;
    let mut line_count = 0usize;
    for _line in text.lines() {
        line_count += 1;
        if line_count > SCREEN_CONTEXT_MAX_LINES {
            truncated = true;
            break;
        }
    }
    if line_count > SCREEN_CONTEXT_MAX_LINES {
        text = text
            .lines()
            .take(SCREEN_CONTEXT_MAX_LINES)
            .collect::<Vec<_>>()
            .join("\n");
    }
    if text.len() > SCREEN_CONTEXT_MAX_TEXT_BYTES {
        truncated = true;
        let mut bounded = String::new();
        for line in text.lines() {
            if bounded.len() >= SCREEN_CONTEXT_MAX_TEXT_BYTES {
                truncated = true;
                break;
            }
            let remaining = SCREEN_CONTEXT_MAX_TEXT_BYTES - bounded.len();
            let mut take = line.len().min(remaining);
            while !line.is_char_boundary(take) {
                take -= 1;
            }
            bounded.push_str(&line[..take]);
            bounded.push('\n');
        }
        let bounded = bounded.trim_end_matches('\n').to_string();
        text = bounded;
    }
    Ok(ScreenContextPayload {
        captured_at: observation.captured_at,
        status,
        text,
        truncated,
    })
}

/// Generates an opaque, high-entropy, process-local identity from the OS
/// cryptographically secure random source.  There is deliberately no
/// sequential counter, no timestamp-derived identity, and no embedded Life or
/// target identity; the output is not predictable by ordinary increment or
/// replay.  Identifier secrecy alone is not authorization.  A failure of the
/// OS random source fails closed with a typed synchronization error instead
/// of panicking.
fn generate_opaque_identity() -> Result<String, ScreenContextError> {
    let mut bytes = [0u8; IDENTITY_HEX_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| ScreenContextError::synchronization_unavailable())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const LIFE_A: &str = "life-a";
    const LIFE_B: &str = "life-b";
    const FENCE_1: ScreenContextSessionFence = ScreenContextSessionFence(1);
    const FENCE_2: ScreenContextSessionFence = ScreenContextSessionFence(2);
    const CONVERSATION_1: &str = "conversation-1";
    const CONVERSATION_2: &str = "conversation-2";
    const REQUEST_1: &str = "request-1";
    const REQUEST_2: &str = "request-2";

    /// Per-instance deterministic clock: tests advance it without sleeping.
    /// It is owned by the broker under test — there is no process-global
    /// test clock.
    #[derive(Clone)]
    struct ManualClock {
        now: Arc<Mutex<Instant>>,
    }

    impl ManualClock {
        fn new() -> Self {
            Self {
                now: Arc::new(Mutex::new(Instant::now())),
            }
        }

        fn advance(&self, duration: Duration) {
            *self.now.lock().unwrap() += duration;
        }
    }

    impl BrokerClock for ManualClock {
        fn now(&self) -> Instant {
            *self.now.lock().unwrap()
        }
    }

    fn broker_with_manual_clock() -> (ScreenContextHandoffBroker, ManualClock) {
        let clock = ManualClock::new();
        let broker = ScreenContextHandoffBroker::with_clock(Box::new(clock.clone()));
        (broker, clock)
    }

    fn observation(
        status: ScreenObservationStatus,
        text: impl Into<String>,
        truncated: bool,
    ) -> ScreenObservation {
        ScreenObservation {
            captured_at: "2026-08-30T00:00:00.000Z".to_string(),
            status,
            text: text.into(),
            truncated,
        }
    }

    fn recognized(text: impl Into<String>) -> ScreenObservation {
        observation(ScreenObservationStatus::Recognized, text, false)
    }

    fn no_text() -> ScreenObservation {
        observation(ScreenObservationStatus::NoText, String::new(), false)
    }

    fn install(
        broker: &ScreenContextHandoffBroker,
        life_id: &str,
        fence: ScreenContextSessionFence,
        observation: ScreenObservation,
    ) -> String {
        broker
            .install_candidate(ScreenContextCandidateInput {
                life_id: life_id.to_string(),
                session_fence: fence,
                observation,
            })
            .expect("candidate installation should succeed")
    }

    fn issue(
        broker: &ScreenContextHandoffBroker,
        candidate_id: &str,
        life_id: &str,
        fence: ScreenContextSessionFence,
    ) -> String {
        broker
            .issue_grant(candidate_id, life_id, fence)
            .expect("grant issuance should succeed")
    }

    fn claim(
        broker: &ScreenContextHandoffBroker,
        life_id: &str,
        fence: ScreenContextSessionFence,
        conversation_id: &str,
        request_id: &str,
    ) -> Result<ScreenContextPayload, ScreenContextError> {
        broker.claim_grant(ScreenContextIds {
            life_id: life_id.to_string(),
            session_fence: fence,
            conversation_id: conversation_id.to_string(),
            request_id: request_id.to_string(),
        })
    }

    fn claim_ok(
        broker: &ScreenContextHandoffBroker,
        life_id: &str,
        fence: ScreenContextSessionFence,
        conversation_id: &str,
        request_id: &str,
    ) -> ScreenContextPayload {
        claim(broker, life_id, fence, conversation_id, request_id).expect("claim should succeed")
    }

    fn assert_empty(broker: &ScreenContextHandoffBroker) {
        let state = broker.state.lock().unwrap();
        assert_eq!(*state, ScreenContextState::Empty, "broker must be EMPTY");
    }

    fn assert_error(
        result: Result<ScreenContextPayload, ScreenContextError>,
        code: ScreenContextErrorCode,
    ) {
        match result {
            Ok(_) => panic!("expected error {code:?} but claim succeeded"),
            Err(error) => assert_eq!(error.code, code),
        }
    }

    #[test]
    fn fresh_broker_is_empty() {
        let broker = ScreenContextHandoffBroker::new();
        assert_empty(&broker);
        // A freshly constructed broker must also have a pristine state with
        // no surviving candidate or grant identity.
        let error = broker
            .issue_grant("any-candidate", LIFE_A, FENCE_1)
            .expect_err("no candidate may issue on a fresh broker");
        assert_eq!(error.code, ScreenContextErrorCode::NoCurrentContext);
    }

    #[test]
    fn candidate_installs_successfully() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let state = broker.state.lock().unwrap();
        match &*state {
            ScreenContextState::Candidate {
                candidate_id: stored,
                life_id,
                session_fence,
                payload,
                created_at,
                deadline,
            } => {
                assert_eq!(stored, &candidate_id);
                assert_eq!(life_id, LIFE_A);
                assert_eq!(*session_fence, FENCE_1);
                assert_eq!(payload.text, "hello");
                assert_eq!(payload.status, ScreenContextTextStatus::Recognized);
                assert!(!payload.truncated);
                assert_eq!(*deadline - *created_at, SCREEN_CONTEXT_HANDOFF_TTL);
            }
            other => panic!("expected Candidate state, got {other:?}"),
        }
    }

    #[test]
    fn new_candidate_replaces_old_candidate() {
        let (broker, _clock) = broker_with_manual_clock();
        let old = install(&broker, LIFE_A, FENCE_1, recognized("old"));
        let new = install(&broker, LIFE_A, FENCE_1, recognized("new"));
        assert_ne!(old, new);
        let error = broker
            .issue_grant(&old, LIFE_A, FENCE_1)
            .expect_err("stale replaced candidate must not issue");
        assert_eq!(error.code, ScreenContextErrorCode::NoCurrentContext);
        let grant_id = issue(&broker, &new, LIFE_A, FENCE_1);
        assert!(!grant_id.is_empty());
    }

    #[test]
    fn new_candidate_replaces_pending_grant() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("first"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let new_candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("second"));
        assert_ne!(new_candidate_id, candidate_id);

        // The replaced pending grant must be gone.
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::NoCurrentContext,
        );
        // The replacement candidate is independently usable.
        let _ = issue(&broker, &new_candidate_id, LIFE_A, FENCE_1);
    }

    #[test]
    fn new_candidate_replaces_bound_grant() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("first"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first_payload = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        let new_candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("second"));

        // The replaced bound grant must be gone, including same-tuple retry.
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::NoCurrentContext,
        );
        let _ = issue(&broker, &new_candidate_id, LIFE_A, FENCE_1);
    }

    #[test]
    fn candidate_bound_to_wrong_life_fails() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let error = broker
            .issue_grant(&candidate_id, LIFE_B, FENCE_1)
            .expect_err("a different Life must not issue this candidate");
        assert_eq!(error.code, ScreenContextErrorCode::LifeMismatch);
    }

    #[test]
    fn candidate_bound_to_wrong_session_fence_fails() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let error = broker
            .issue_grant(&candidate_id, LIFE_A, FENCE_2)
            .expect_err("a different session fence must not issue this candidate");
        assert_eq!(error.code, ScreenContextErrorCode::SessionFenceMismatch);
    }

    #[test]
    fn no_text_candidate_is_allowed_to_install() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, no_text());
        let state = broker.state.lock().unwrap();
        match &*state {
            ScreenContextState::Candidate {
                candidate_id: stored,
                payload,
                ..
            } => {
                assert_eq!(stored, &candidate_id);
                assert_eq!(payload.status, ScreenContextTextStatus::NoText);
                assert!(payload.text.is_empty());
            }
            other => panic!("expected Candidate state, got {other:?}"),
        }
    }

    #[test]
    fn no_text_candidate_cannot_issue_a_grant() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, no_text());
        let error = broker
            .issue_grant(&candidate_id, LIFE_A, FENCE_1)
            .expect_err("NoText must never produce a grant");
        assert_eq!(error.code, ScreenContextErrorCode::NoUsableScreenContext);
        // The failed issuance must not fabricate a grant and must not
        // destroy the installed NoText candidate: the state is still the
        // candidate (NoText is a valid installed candidate).
        let state = broker.state.lock().unwrap();
        match &*state {
            ScreenContextState::Candidate { .. } => {}
            other => panic!("expected the NoText Candidate to remain, got {other:?}"),
        }
    }

    #[test]
    fn no_text_candidate_never_produces_an_empty_fake_grant() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, no_text());
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::NoCurrentContext,
        );
        assert!(broker.issue_grant(&candidate_id, LIFE_A, FENCE_1).is_err());
        // No empty grant was fabricated: the state remains a candidate that
        // still cannot bind anything.
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::NoCurrentContext,
        );
    }

    #[test]
    fn expiry_begins_at_candidate_creation() {
        let (broker, clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        // The TTL clock started at candidate creation: 9 minutes in, the
        // candidate is still alive (TTL is 10 minutes).
        clock.advance(Duration::from_secs(9 * 60));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        assert!(!grant_id.is_empty());
        // At T0 + 10 min the issued grant is already expired — issuance never
        // reset the lifetime clock.
        clock.advance(Duration::from_secs(60));
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::Expired,
        );
    }

    #[test]
    fn grant_issuance_does_not_refresh_ttl() {
        let (broker, clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        // Use the grant at T0 + 8 min.
        clock.advance(Duration::from_secs(8 * 60));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        // The grant expires at approximately T0 + 10 min, not T0 + 18 min.
        clock.advance(Duration::from_secs(2 * 60));
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::Expired,
        );
    }

    #[test]
    fn expired_candidate_fails() {
        let (broker, clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        clock.advance(SCREEN_CONTEXT_HANDOFF_TTL);
        let error = broker
            .issue_grant(&candidate_id, LIFE_A, FENCE_1)
            .expect_err("an expired candidate must not issue");
        assert_eq!(error.code, ScreenContextErrorCode::Expired);
    }

    #[test]
    fn expired_pending_grant_fails() {
        let (broker, clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        clock.advance(SCREEN_CONTEXT_HANDOFF_TTL);
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::Expired,
        );
    }

    #[test]
    fn expired_bound_grant_cannot_be_reclaimed() {
        let (broker, clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        clock.advance(SCREEN_CONTEXT_HANDOFF_TTL);
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::Expired,
        );
        assert!(
            broker
                .retire_bound_grant(&grant_id, LIFE_A, CONVERSATION_1, REQUEST_1)
                .is_err(),
            "an expired bound grant must not be retired"
        );
    }

    #[test]
    fn candidate_to_grant_is_a_one_way_move() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let state = broker.state.lock().unwrap();
        match &*state {
            ScreenContextState::GrantPending {
                grant_id: stored,
                payload,
                ..
            } => {
                assert_eq!(stored, &grant_id);
                assert_eq!(payload.text, "hello");
            }
            other => panic!("expected GrantPending state, got {other:?}"),
        }
        // The candidate identity is unusable after the move.  The state lock
        // must be dropped first: issuing again would deadlock on the
        // non-reentrant canonical mutex.
        drop(state);
        let error = broker
            .issue_grant(&candidate_id, LIFE_A, FENCE_1)
            .expect_err("the moved candidate identity must be unusable");
        assert_eq!(error.code, ScreenContextErrorCode::NoCurrentContext);
    }

    #[test]
    fn first_claim_binds_once() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let payload = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        assert_eq!(payload.text, "hello");
        let state = broker.state.lock().unwrap();
        match &*state {
            ScreenContextState::GrantBound {
                grant_id: stored,
                life_id,
                session_fence,
                conversation_id,
                request_id,
                ..
            } => {
                assert_eq!(stored, &grant_id);
                assert_eq!(life_id, LIFE_A);
                assert_eq!(*session_fence, FENCE_1);
                assert_eq!(conversation_id, CONVERSATION_1);
                assert_eq!(request_id, REQUEST_1);
            }
            other => panic!("expected GrantBound state, got {other:?}"),
        }
    }

    #[test]
    fn same_exact_tuple_is_idempotent_with_identical_payload() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("same text"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        let second = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        assert_eq!(
            first, second,
            "same-request retry must return an identical payload"
        );
    }

    #[test]
    fn different_request_is_rejected() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_2),
            ScreenContextErrorCode::GrantAlreadyBound,
        );
    }

    #[test]
    fn different_conversation_is_rejected() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_2, REQUEST_1),
            ScreenContextErrorCode::GrantAlreadyBound,
        );
    }

    #[test]
    fn different_life_is_rejected() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        assert_error(
            claim(&broker, LIFE_B, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::LifeMismatch,
        );
    }

    #[test]
    fn different_session_fence_is_rejected() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        assert_error(
            claim(&broker, LIFE_A, FENCE_2, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::SessionFenceMismatch,
        );
    }

    #[test]
    fn same_life_after_disarm_rearm_with_new_fence_is_rejected() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        // The same Life after disarm/re-arm carries a new session fence; the
        // bound grant must never be rebound to the new fence.
        assert_error(
            claim(&broker, LIFE_A, FENCE_2, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::SessionFenceMismatch,
        );
        // The original binding is untouched by the failed rebinding attempt:
        // the true bound scope still retries and still retires.
        let _retry = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        broker
            .retire_bound_grant(&grant_id, LIFE_A, CONVERSATION_1, REQUEST_1)
            .expect("the original bound scope must still retire");
        assert_empty(&broker);
    }

    #[test]
    fn cancel_candidate_returns_to_empty() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        broker.cancel().expect("cancellation must succeed");
        assert_empty(&broker);
        let error = broker
            .issue_grant(&candidate_id, LIFE_A, FENCE_1)
            .expect_err("a cancelled candidate identity must not be reusable");
        assert_eq!(error.code, ScreenContextErrorCode::NoCurrentContext);
    }

    #[test]
    fn cancel_pending_grant_returns_to_empty() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        broker.cancel().expect("cancellation must succeed");
        assert_empty(&broker);
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::NoCurrentContext,
        );
        assert!(
            broker
                .retire_bound_grant(&grant_id, LIFE_A, CONVERSATION_1, REQUEST_1)
                .is_err(),
            "a cancelled grant identity must not be reusable"
        );
    }

    #[test]
    fn cancel_bound_grant_returns_to_empty() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        broker.cancel().expect("cancellation must succeed");
        assert_empty(&broker);
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1),
            ScreenContextErrorCode::NoCurrentContext,
        );
        assert!(
            broker
                .retire_bound_grant(&grant_id, LIFE_A, CONVERSATION_1, REQUEST_1)
                .is_err(),
            "a cancelled bound grant must not be reusable"
        );
    }

    #[test]
    fn correct_bound_scope_retires_to_empty() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        broker
            .retire_bound_grant(&grant_id, LIFE_A, CONVERSATION_1, REQUEST_1)
            .expect("a correctly scoped retirement must succeed");
        assert_empty(&broker);
    }

    #[test]
    fn mismatched_retirement_scope_does_not_destroy_authority() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let _first = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);

        let cases: Vec<(&str, &str, &str)> = vec![
            ("wrong-grant", CONVERSATION_1, REQUEST_1),
            (grant_id.as_str(), CONVERSATION_2, REQUEST_1),
            (grant_id.as_str(), CONVERSATION_1, REQUEST_2),
            (grant_id.as_str(), "conversation-other", "request-other"),
        ];
        for (wrong_grant, wrong_conversation, wrong_request) in cases {
            let result =
                broker.retire_bound_grant(wrong_grant, LIFE_A, wrong_conversation, wrong_request);
            assert!(
                result.is_err(),
                "mismatched retirement scope must fail: {wrong_grant} / {wrong_conversation} / {wrong_request}"
            );
        }

        // The original authority is untouched and the true scope still retires.
        let _retry = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        broker
            .retire_bound_grant(&grant_id, LIFE_A, CONVERSATION_1, REQUEST_1)
            .expect("the true scope must still retire");
        assert_empty(&broker);
    }

    #[test]
    fn replacement_revokes_stale_bound_and_pending_authority() {
        let (broker, _clock) = broker_with_manual_clock();
        let first_candidate = install(&broker, LIFE_A, FENCE_1, recognized("first"));
        let first_grant = issue(&broker, &first_candidate, LIFE_A, FENCE_1);
        let _first_bound = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        // Replacing the bound grant revokes the old authority: the replaced
        // grant can never be retired, and the state now holds a fresh
        // independent grant (the old bound tuple is no longer special).
        let second_candidate = install(&broker, LIFE_A, FENCE_1, recognized("second"));
        let second_grant = issue(&broker, &second_candidate, LIFE_A, FENCE_1);
        assert!(
            broker
                .retire_bound_grant(&first_grant, LIFE_A, CONVERSATION_1, REQUEST_1)
                .is_err(),
            "a replaced bound grant must not be retired"
        );

        // The replacement grant is a fresh independent authority: it binds to
        // a new scope and is revoked by one more replacement.  Installing the
        // third candidate alone (without issuing) already revokes the second
        // bound grant.
        let _second_bound = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_2, REQUEST_2);
        let third_candidate = install(&broker, LIFE_A, FENCE_1, recognized("third"));
        assert_error(
            claim(&broker, LIFE_A, FENCE_1, CONVERSATION_2, REQUEST_2),
            ScreenContextErrorCode::NoCurrentContext,
        );
        assert!(
            broker
                .retire_bound_grant(&second_grant, LIFE_A, CONVERSATION_2, REQUEST_2)
                .is_err(),
            "a replaced pending grant must not be retired"
        );
        // The fresh third candidate remains independently usable.
        let _third_grant = issue(&broker, &third_candidate, LIFE_A, FENCE_1);
    }

    #[test]
    fn competing_claims_serialize_to_exactly_one_winner() {
        let broker = Arc::new(ScreenContextHandoffBroker::new());
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);

        let results = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for (conversation_id, request_id) in
            [(CONVERSATION_1, REQUEST_1), (CONVERSATION_2, REQUEST_2)]
        {
            let broker = Arc::clone(&broker);
            let results = Arc::clone(&results);
            handles.push(std::thread::spawn(move || {
                let result = broker.claim_grant(ScreenContextIds {
                    life_id: LIFE_A.to_string(),
                    session_fence: FENCE_1,
                    conversation_id: conversation_id.to_string(),
                    request_id: request_id.to_string(),
                });
                results.lock().unwrap().push(result);
            }));
        }
        for handle in handles {
            handle.join().expect("claim thread must not panic");
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 2, "both competing claims must complete");
        let winners = results.iter().filter(|result| result.is_ok()).count();
        assert_eq!(
            winners, 1,
            "exactly one canonical binding winner is required"
        );
        let losers = results.iter().filter(|result| result.is_err()).count();
        assert_eq!(losers, 1, "exactly one loser must fail closed");
        drop(results);

        // No partial state: the canonical state is a fully bound grant, and
        // the winner's tuple can retry while the loser's tuple stays rejected.
        let state = broker.state.lock().unwrap();
        match &*state {
            ScreenContextState::GrantBound { .. } => {}
            other => panic!("expected a fully bound grant, got {other:?}"),
        }
        drop(state);

        let winner_tuple = if claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1).is_ok() {
            (CONVERSATION_1, REQUEST_1)
        } else {
            (CONVERSATION_2, REQUEST_2)
        };
        let (winning_conversation, winning_request) = winner_tuple;
        let (losing_conversation, losing_request) = if winner_tuple == (CONVERSATION_1, REQUEST_1) {
            (CONVERSATION_2, REQUEST_2)
        } else {
            (CONVERSATION_1, REQUEST_1)
        };
        // The loser scope stays rejected.
        assert_error(
            claim(
                &broker,
                LIFE_A,
                FENCE_1,
                losing_conversation,
                losing_request,
            ),
            ScreenContextErrorCode::GrantAlreadyBound,
        );
        // The winner scope remains claimable (same-request retry).
        let retry = claim_ok(
            &broker,
            LIFE_A,
            FENCE_1,
            winning_conversation,
            winning_request,
        );
        assert_eq!(retry.text, "hello");
    }

    #[test]
    fn poisoned_lock_fails_closed_for_authority_broadening() {
        let (broker, _clock) = broker_with_manual_clock();
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        // Poison the lock by panicking while its guard is held.  The panic is
        // caught locally; the mutex remains poisoned afterwards.
        let poisoned = Mutex::new(ScreenContextState::Empty);
        let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = poisoned.lock().unwrap();
            panic!("intentional lock poison for the fail-closed test");
        }));
        assert!(poison_result.is_err(), "the poison panic must be caught");
        let poisoned_broker = ScreenContextHandoffBroker {
            state: poisoned,
            clock: Box::new(InstantBrokerClock),
        };

        let error = poisoned_broker
            .install_candidate(ScreenContextCandidateInput {
                life_id: LIFE_A.to_string(),
                session_fence: FENCE_1,
                observation: recognized("hello"),
            })
            .expect_err("install must fail closed on a poisoned lock");
        assert_eq!(
            error.code,
            ScreenContextErrorCode::SynchronizationUnavailable
        );

        let error = poisoned_broker
            .issue_grant(&candidate_id, LIFE_A, FENCE_1)
            .expect_err("issue must fail closed on a poisoned lock");
        assert_eq!(
            error.code,
            ScreenContextErrorCode::SynchronizationUnavailable
        );

        assert_error(
            poisoned_broker.claim_grant(ScreenContextIds {
                life_id: LIFE_A.to_string(),
                session_fence: FENCE_1,
                conversation_id: CONVERSATION_1.to_string(),
                request_id: REQUEST_1.to_string(),
            }),
            ScreenContextErrorCode::SynchronizationUnavailable,
        );
    }

    #[test]
    fn empty_arguments_are_rejected() {
        let (broker, _clock) = broker_with_manual_clock();
        let error = broker
            .install_candidate(ScreenContextCandidateInput {
                life_id: "  ".to_string(),
                session_fence: FENCE_1,
                observation: recognized("hello"),
            })
            .expect_err("an empty Life must be rejected");
        assert_eq!(error.code, ScreenContextErrorCode::InvalidArgument);
        assert_empty(&broker);

        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let error = claim(&broker, LIFE_A, FENCE_1, " ", REQUEST_1)
            .expect_err("an empty conversation identity must be rejected");
        assert_eq!(error.code, ScreenContextErrorCode::InvalidArgument);
        let error = claim(&broker, LIFE_A, FENCE_1, CONVERSATION_1, "  ")
            .expect_err("an empty request identity must be rejected");
        assert_eq!(error.code, ScreenContextErrorCode::InvalidArgument);
        // The grant is untouched by rejected invalid claims.
        let _retry = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
    }

    #[test]
    fn production_source_has_no_frame_native_target_window_or_process_fields() {
        let source = include_str!("screen_context.rs");
        let production_source = source
            .split_once("#[cfg(test)]")
            .map_or(source, |(production, _)| production);
        let forbidden = [
            "ScreenFrame",
            "BGRA",
            "GraphicsCaptureItem",
            "hwnd",
            "process_path",
            "window_title",
            "monitor_identity",
            "ocr_geometry",
            "OcrResult",
            "recognized_lines",
            "ocr_engine",
        ];
        for token in forbidden {
            assert!(
                !production_source.contains(token),
                "forbidden frame/native target/window/process token appeared in the production source: {token}"
            );
        }
    }

    #[test]
    fn payload_bounds_match_frozen_d23_limits() {
        // The candidate must never raise the frozen D23 observation bounds.
        assert_eq!(
            SCREEN_CONTEXT_MAX_TEXT_BYTES,
            super::super::screen_ocr::MAX_OBSERVATION_TEXT_BYTES
        );
        assert_eq!(
            SCREEN_CONTEXT_MAX_LINES,
            super::super::screen_ocr::MAX_OBSERVATION_LINES
        );

        let (broker, _clock) = broker_with_manual_clock();
        let oversized = "x".repeat(40 * 1024);
        let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized(&oversized));
        let _grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
        let payload = claim_ok(&broker, LIFE_A, FENCE_1, CONVERSATION_1, REQUEST_1);
        assert!(payload.truncated);
        assert!(
            payload.text.len() <= SCREEN_CONTEXT_MAX_TEXT_BYTES,
            "payload text must respect the frozen 32 KiB bound"
        );
        assert_eq!(
            payload.text.len(),
            32 * 1024,
            "bounded text must keep the full 32 KiB"
        );
    }

    #[test]
    fn identities_are_opaque_high_entropy_and_distinct() {
        let (broker, _clock) = broker_with_manual_clock();
        let mut candidate_ids = std::collections::HashSet::new();
        let mut grant_ids = std::collections::HashSet::new();
        for _ in 0..64 {
            let candidate_id = install(&broker, LIFE_A, FENCE_1, recognized("hello"));
            let grant_id = issue(&broker, &candidate_id, LIFE_A, FENCE_1);
            candidate_ids.insert(candidate_id);
            grant_ids.insert(grant_id);
            broker.cancel().expect("cancellation must succeed");
        }
        assert_eq!(candidate_ids.len(), 64, "candidate IDs must not repeat");
        assert_eq!(grant_ids.len(), 64, "grant IDs must not repeat");
        for identity in candidate_ids.iter().chain(grant_ids.iter()) {
            assert_eq!(identity.len(), IDENTITY_HEX_BYTES * 2);
            assert!(identity.chars().all(|c| c.is_ascii_hexdigit()));
        }
        // Candidate ID and grant ID are distinct authorities: a candidate ID
        // must never be usable as a grant ID or vice versa.
        assert!(candidate_ids.is_disjoint(&grant_ids));
    }
}
