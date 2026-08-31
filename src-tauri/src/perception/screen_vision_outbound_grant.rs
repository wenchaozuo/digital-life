//! D25-D2 process-local one-shot screen-vision outbound authorization.
//!
//! This module owns one exact READY/BOUND/CONSUMED authorization slot for a
//! future delivery.  It composes existing local authorities and the frozen D1
//! destination value, but it never performs transport, resolves credentials,
//! reads image bytes, or exposes an IPC surface.

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use super::screen_policy::{
    authorize_screen_perception, ScreenPerceptionRepository, ScreenPerceptionSessionGate,
};
use super::screen_vision_outbound_candidate::{
    ScreenVisionOutboundCandidateBroker, ScreenVisionOutboundCandidateErrorCode,
};
use super::screen_vision_outbound_destination::ScreenVisionOutboundDestinationBinding;
use super::screen_vision_outbound_policy::{
    validate_screen_vision_outbound_policy_state, ScreenVisionOutboundPolicyRepository,
};

pub(crate) const SCREEN_VISION_OUTBOUND_READY_GRANT_TTL: Duration = Duration::from_secs(2 * 60);

const MAX_ID_CHARACTERS: usize = 128;
const GRANT_ID_RANDOM_BYTES: usize = 16;
const GRANT_ID_HEX_LENGTH: usize = GRANT_ID_RANDOM_BYTES * 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundGrantErrorCode {
    InvalidArgument,
    CandidateUnavailable,
    LocalScreenAuthorityUnavailable,
    SessionFenceMismatch,
    OutboundPolicyUnavailable,
    OutboundPolicyMismatch,
    ConfirmationEventConflict,
    GrantMismatch,
    GrantExpired,
    GrantConsumed,
    CandidateConsumed,
    GrantInUse,
    DeliveryConflict,
    DestinationMismatch,
    SynchronizationUnavailable,
    RandomUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundGrantError {
    code: ScreenVisionOutboundGrantErrorCode,
}

impl ScreenVisionOutboundGrantError {
    const fn new(code: ScreenVisionOutboundGrantErrorCode) -> Self {
        Self { code }
    }

    pub(crate) const fn code(self) -> ScreenVisionOutboundGrantErrorCode {
        self.code
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundGrantState {
    Ready,
    Bound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScreenVisionOutboundGrantTerminalReason {
    Expired,
    Revoked,
    Succeeded,
    ProviderResponded,
    Abandoned,
}

/// Bounded grant metadata.  Destination URL/model details are intentionally
/// absent; the full D1 binding remains private inside the grant record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScreenVisionOutboundGrantMetadata {
    pub(crate) grant_id: String,
    pub(crate) confirmation_event_id: String,
    pub(crate) candidate_id: String,
    pub(crate) life_id: String,
    pub(crate) outbound_policy_revision: i64,
    pub(crate) state: ScreenVisionOutboundGrantState,
    pub(crate) age: Duration,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundGrantIssueOutcome {
    Issued(ScreenVisionOutboundGrantMetadata),
    Replayed(ScreenVisionOutboundGrantMetadata),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ScreenVisionOutboundGrantClaimOutcome {
    Claimed(ScreenVisionOutboundGrantMetadata),
    Replayed(ScreenVisionOutboundGrantMetadata),
}

struct ScreenVisionOutboundGrantRecord {
    grant_id: String,
    confirmation_event_id: String,
    candidate_id: String,
    life_id: String,
    screen_session_fence: String,
    outbound_policy_revision: i64,
    destination_binding: ScreenVisionOutboundDestinationBinding,
    created_at: Instant,
}

enum ScreenVisionOutboundGrantStateSlot {
    Empty,
    Ready(ScreenVisionOutboundGrantRecord),
    Bound {
        grant: ScreenVisionOutboundGrantRecord,
        delivery_id: String,
    },
    Consumed {
        grant: ScreenVisionOutboundGrantRecord,
        terminal_reason: ScreenVisionOutboundGrantTerminalReason,
    },
}

trait GrantClock: Send + Sync {
    fn now(&self) -> Instant;
}

struct SystemGrantClock;

impl GrantClock for SystemGrantClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

trait GrantIdSource: Send + Sync {
    fn generate(&self) -> Result<String, ScreenVisionOutboundGrantError>;
}

struct CsprngGrantIdSource;

impl GrantIdSource for CsprngGrantIdSource {
    fn generate(&self) -> Result<String, ScreenVisionOutboundGrantError> {
        let mut random = [0_u8; GRANT_ID_RANDOM_BYTES];
        getrandom::fill(&mut random)
            .map_err(|_| grant_error(ScreenVisionOutboundGrantErrorCode::RandomUnavailable))?;

        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut grant_id = String::with_capacity(GRANT_ID_HEX_LENGTH);
        for byte in random {
            grant_id.push(char::from(HEX[usize::from(byte >> 4)]));
            grant_id.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        Ok(grant_id)
    }
}

/// The sole process-local D25-D2 grant slot.
pub(crate) struct ScreenVisionOutboundGrantBroker {
    state: Mutex<ScreenVisionOutboundGrantStateSlot>,
    clock: Arc<dyn GrantClock>,
    id_source: Arc<dyn GrantIdSource>,
    #[cfg(test)]
    terminal_retirement_failures: AtomicUsize,
}

impl ScreenVisionOutboundGrantBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(ScreenVisionOutboundGrantStateSlot::Empty),
            clock: Arc::new(SystemGrantClock),
            id_source: Arc::new(CsprngGrantIdSource),
            #[cfg(test)]
            terminal_retirement_failures: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    fn with_clock_and_id_source(
        clock: Arc<dyn GrantClock>,
        id_source: Arc<dyn GrantIdSource>,
    ) -> Self {
        Self {
            state: Mutex::new(ScreenVisionOutboundGrantStateSlot::Empty),
            clock,
            id_source,
            terminal_retirement_failures: AtomicUsize::new(0),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_next_terminal_retirement_for_test(&self) {
        self.terminal_retirement_failures
            .fetch_add(1, Ordering::AcqRel);
    }

    #[cfg(test)]
    pub(crate) fn install_bound_for_test(
        &self,
        grant_id: &str,
        confirmation_event_id: &str,
        candidate_id: &str,
        life_id: &str,
        screen_session_fence: &str,
        outbound_policy_revision: i64,
        destination_binding: ScreenVisionOutboundDestinationBinding,
        delivery_id: &str,
    ) {
        let mut state = self
            .state
            .lock()
            .expect("grant state should initially lock");
        *state = ScreenVisionOutboundGrantStateSlot::Bound {
            grant: ScreenVisionOutboundGrantRecord {
                grant_id: grant_id.to_string(),
                confirmation_event_id: confirmation_event_id.to_string(),
                candidate_id: candidate_id.to_string(),
                life_id: life_id.to_string(),
                screen_session_fence: screen_session_fence.to_string(),
                outbound_policy_revision,
                destination_binding,
                created_at: Instant::now(),
            },
            delivery_id: delivery_id.to_string(),
        };
    }

    /// Issues a grant only after deriving every scope dimension from the
    /// exact current C2 candidate and re-reading D23/D25 authorities.
    pub(crate) fn issue_user_confirmed_screen_vision_grant(
        &self,
        confirmation_event_id: &str,
        candidate_id: &str,
        destination_binding: ScreenVisionOutboundDestinationBinding,
        screen_repository: &dyn ScreenPerceptionRepository,
        session_gate: &ScreenPerceptionSessionGate,
        outbound_repository: &dyn ScreenVisionOutboundPolicyRepository,
        candidate_broker: &ScreenVisionOutboundCandidateBroker,
    ) -> Result<ScreenVisionOutboundGrantIssueOutcome, ScreenVisionOutboundGrantError> {
        validate_id(confirmation_event_id)?;
        validate_id(candidate_id)?;

        let candidate = candidate_broker
            .get_exact(candidate_id)
            .map_err(map_candidate_error)?;
        let life_id = candidate.life_id.as_str();
        let candidate_fence = candidate.screen_session_fence.as_str();
        let candidate_revision = candidate.outbound_policy_revision;

        authorize_screen_perception(screen_repository, session_gate, life_id).map_err(|_| {
            grant_error(ScreenVisionOutboundGrantErrorCode::LocalScreenAuthorityUnavailable)
        })?;
        let current_fence = session_gate.life_fence_for(life_id).ok_or_else(|| {
            grant_error(ScreenVisionOutboundGrantErrorCode::LocalScreenAuthorityUnavailable)
        })?;
        let canonical_fence = current_fence.to_string();
        if canonical_fence != candidate_fence {
            return Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::SessionFenceMismatch,
            ));
        }

        let current_revision = read_outbound_policy_revision(outbound_repository, life_id)
            .map_err(|_| {
                grant_error(ScreenVisionOutboundGrantErrorCode::OutboundPolicyUnavailable)
            })?;
        if current_revision != candidate_revision {
            return Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::OutboundPolicyMismatch,
            ));
        }

        let mut state = self.lock_state()?;
        let now = self.clock.now();
        consume_ready_if_needed(&mut state, now);

        if let ScreenVisionOutboundGrantStateSlot::Bound { .. } = &*state {
            return Err(grant_error(ScreenVisionOutboundGrantErrorCode::GrantInUse));
        }

        if let ScreenVisionOutboundGrantStateSlot::Ready(current) = &*state {
            if current.confirmation_event_id == confirmation_event_id {
                if current.candidate_id == candidate_id
                    && current.life_id == life_id
                    && current.screen_session_fence == canonical_fence
                    && current.outbound_policy_revision == candidate_revision
                    && current.destination_binding == destination_binding
                {
                    return Ok(ScreenVisionOutboundGrantIssueOutcome::Replayed(
                        grant_metadata(current, ScreenVisionOutboundGrantState::Ready, now),
                    ));
                }
                return Err(grant_error(
                    ScreenVisionOutboundGrantErrorCode::ConfirmationEventConflict,
                ));
            }
            if current.candidate_id == candidate_id {
                return Err(grant_error(ScreenVisionOutboundGrantErrorCode::GrantInUse));
            }
        }

        if let ScreenVisionOutboundGrantStateSlot::Consumed {
            grant,
            terminal_reason,
        } = &*state
        {
            if grant.confirmation_event_id == confirmation_event_id {
                return Err(
                    if grant.candidate_id == candidate_id
                        && grant.life_id == life_id
                        && grant.screen_session_fence == canonical_fence
                        && grant.outbound_policy_revision == candidate_revision
                        && grant.destination_binding == destination_binding
                    {
                        terminal_error(*terminal_reason)
                    } else {
                        grant_error(ScreenVisionOutboundGrantErrorCode::ConfirmationEventConflict)
                    },
                );
            }
            if grant.candidate_id == candidate_id {
                return Err(grant_error(
                    ScreenVisionOutboundGrantErrorCode::CandidateConsumed,
                ));
            }
        }

        // This is the final exact C2 candidate check before replacing the
        // process-local READY slot.  A later delivery layer must revalidate
        // again because these independent local authorities have no shared
        // transaction.
        candidate_broker
            .validate_exact_candidate(candidate_id, life_id, &canonical_fence, candidate_revision)
            .map_err(map_candidate_error)?;

        // Generate before mutating the existing READY state.  Random failure
        // therefore leaves that state untouched.
        let grant_id = self.id_source.generate()?;
        let grant = ScreenVisionOutboundGrantRecord {
            grant_id,
            confirmation_event_id: confirmation_event_id.to_string(),
            candidate_id: candidate_id.to_string(),
            life_id: life_id.to_string(),
            screen_session_fence: canonical_fence,
            outbound_policy_revision: candidate_revision,
            destination_binding,
            created_at: now,
        };
        let metadata = grant_metadata(&grant, ScreenVisionOutboundGrantState::Ready, now);
        *state = ScreenVisionOutboundGrantStateSlot::Ready(grant);
        Ok(ScreenVisionOutboundGrantIssueOutcome::Issued(metadata))
    }

    /// Returns bounded metadata only.  READY expires at the exact monotonic
    /// TTL and becomes a terminal tombstone; BOUND is never auto-expired by
    /// that TTL.
    pub(crate) fn get_exact(
        &self,
        grant_id: &str,
    ) -> Result<ScreenVisionOutboundGrantMetadata, ScreenVisionOutboundGrantError> {
        validate_id(grant_id)?;
        let mut state = self.lock_state()?;
        let now = self.clock.now();
        consume_ready_if_needed(&mut state, now);

        match &*state {
            ScreenVisionOutboundGrantStateSlot::Empty => Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::GrantMismatch,
            )),
            ScreenVisionOutboundGrantStateSlot::Ready(grant) => {
                if grant.grant_id != grant_id {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                    ));
                }
                Ok(grant_metadata(
                    grant,
                    ScreenVisionOutboundGrantState::Ready,
                    now,
                ))
            }
            ScreenVisionOutboundGrantStateSlot::Bound { grant, .. } => {
                if grant.grant_id != grant_id {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                    ));
                }
                Ok(grant_metadata(
                    grant,
                    ScreenVisionOutboundGrantState::Bound,
                    now,
                ))
            }
            ScreenVisionOutboundGrantStateSlot::Consumed {
                grant,
                terminal_reason,
            } => {
                if grant.grant_id != grant_id {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                    ));
                }
                Err(terminal_error(*terminal_reason))
            }
        }
    }

    /// Revokes only an exact, still-READY grant.  BOUND has no generic revoke
    /// path and must be retired only by its exact delivery owner.
    pub(crate) fn revoke_ready_exact(
        &self,
        grant_id: &str,
    ) -> Result<(), ScreenVisionOutboundGrantError> {
        validate_id(grant_id)?;
        let mut state = self.lock_state()?;
        let now = self.clock.now();
        consume_ready_if_needed(&mut state, now);

        match &*state {
            ScreenVisionOutboundGrantStateSlot::Ready(grant) if grant.grant_id == grant_id => {
                let grant =
                    match std::mem::replace(&mut *state, ScreenVisionOutboundGrantStateSlot::Empty)
                    {
                        ScreenVisionOutboundGrantStateSlot::Ready(grant) => grant,
                        _ => unreachable!("grant state cannot change while its mutex is held"),
                    };
                *state = ScreenVisionOutboundGrantStateSlot::Consumed {
                    grant,
                    terminal_reason: ScreenVisionOutboundGrantTerminalReason::Revoked,
                };
                Ok(())
            }
            ScreenVisionOutboundGrantStateSlot::Bound { grant, .. }
                if grant.grant_id == grant_id =>
            {
                Err(grant_error(ScreenVisionOutboundGrantErrorCode::GrantInUse))
            }
            ScreenVisionOutboundGrantStateSlot::Consumed {
                grant,
                terminal_reason,
            } if grant.grant_id == grant_id => Err(terminal_error(*terminal_reason)),
            _ => Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::GrantMismatch,
            )),
        }
    }

    /// Atomically claims the exact READY grant for one opaque future delivery
    /// identity.  This method performs no external operation.  A future
    /// delivery layer must independently revalidate the current C2 candidate,
    /// D23 authority/fence, D25 revision, destination, and send policy.
    pub(crate) fn claim_exact_for_delivery(
        &self,
        grant_id: &str,
        delivery_id: &str,
        candidate_id: &str,
        destination_binding: ScreenVisionOutboundDestinationBinding,
    ) -> Result<ScreenVisionOutboundGrantClaimOutcome, ScreenVisionOutboundGrantError> {
        validate_id(grant_id)?;
        validate_id(delivery_id)?;
        validate_id(candidate_id)?;

        let mut state = self.lock_state()?;
        let now = self.clock.now();
        consume_ready_if_needed(&mut state, now);

        match &*state {
            ScreenVisionOutboundGrantStateSlot::Empty => {
                return Err(grant_error(
                    ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                ));
            }
            ScreenVisionOutboundGrantStateSlot::Ready(grant) => {
                if grant.grant_id != grant_id {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                    ));
                }
                if grant.candidate_id != candidate_id {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                    ));
                }
                if grant.destination_binding != destination_binding {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::DestinationMismatch,
                    ));
                }
            }
            ScreenVisionOutboundGrantStateSlot::Bound {
                grant,
                delivery_id: bound_delivery_id,
            } => {
                if grant.grant_id != grant_id {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                    ));
                }
                if grant.candidate_id != candidate_id {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                    ));
                }
                if grant.destination_binding != destination_binding {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::DestinationMismatch,
                    ));
                }
                if bound_delivery_id == delivery_id {
                    return Ok(ScreenVisionOutboundGrantClaimOutcome::Replayed(
                        grant_metadata(grant, ScreenVisionOutboundGrantState::Bound, now),
                    ));
                }
                return Err(grant_error(
                    ScreenVisionOutboundGrantErrorCode::DeliveryConflict,
                ));
            }
            ScreenVisionOutboundGrantStateSlot::Consumed {
                grant,
                terminal_reason,
            } => {
                if grant.grant_id != grant_id {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                    ));
                }
                return Err(terminal_error(*terminal_reason));
            }
        }

        let ready_grant =
            match std::mem::replace(&mut *state, ScreenVisionOutboundGrantStateSlot::Empty) {
                ScreenVisionOutboundGrantStateSlot::Ready(grant) => grant,
                _ => unreachable!("grant state cannot change while its mutex is held"),
            };
        *state = ScreenVisionOutboundGrantStateSlot::Bound {
            grant: ready_grant,
            delivery_id: delivery_id.to_string(),
        };

        let ScreenVisionOutboundGrantStateSlot::Bound { grant, .. } = &*state else {
            unreachable!("claim must install BOUND state");
        };
        Ok(ScreenVisionOutboundGrantClaimOutcome::Claimed(
            grant_metadata(grant, ScreenVisionOutboundGrantState::Bound, now),
        ))
    }

    /// Retires only an exact BOUND grant owned by the exact delivery identity
    /// and records it as a terminal tombstone.  Wrong or stale completion
    /// identities cannot clear newer state.
    pub(crate) fn retire_bound_after_success(
        &self,
        grant_id: &str,
        delivery_id: &str,
    ) -> Result<(), ScreenVisionOutboundGrantError> {
        self.retire_bound_exact(
            grant_id,
            delivery_id,
            ScreenVisionOutboundGrantTerminalReason::Succeeded,
        )
    }

    /// Retires the exact BOUND grant after any definite provider HTTP
    /// response, including a non-2xx status.  A response proves the one-shot
    /// request reached the provider, so routine resend is not permitted.
    pub(crate) fn retire_bound_after_provider_response(
        &self,
        grant_id: &str,
        delivery_id: &str,
    ) -> Result<(), ScreenVisionOutboundGrantError> {
        self.retire_bound_exact(
            grant_id,
            delivery_id,
            ScreenVisionOutboundGrantTerminalReason::ProviderResponded,
        )
    }

    /// Terminally abandons the exact idle BOUND grant.  It never changes a
    /// BOUND grant back to READY and cannot race a send while the caller owns
    /// the separate Vision delivery operation permit.
    pub(crate) fn abandon_bound_exact(
        &self,
        grant_id: &str,
        delivery_id: &str,
    ) -> Result<(), ScreenVisionOutboundGrantError> {
        self.retire_bound_exact(
            grant_id,
            delivery_id,
            ScreenVisionOutboundGrantTerminalReason::Abandoned,
        )
    }

    /// Revalidates exact BOUND ownership without changing its state.  D26's
    /// final byte-send guard uses this after the transport handshake and
    /// immediately before the only request send.
    pub(crate) fn validate_bound_exact(
        &self,
        grant_id: &str,
        delivery_id: &str,
        candidate_id: &str,
        life_id: &str,
        screen_session_fence: &str,
        outbound_policy_revision: i64,
        destination_binding: &ScreenVisionOutboundDestinationBinding,
    ) -> Result<ScreenVisionOutboundGrantMetadata, ScreenVisionOutboundGrantError> {
        validate_id(grant_id)?;
        validate_id(delivery_id)?;
        validate_id(candidate_id)?;
        validate_id(life_id)?;
        validate_id(screen_session_fence)?;
        if outbound_policy_revision < 1 {
            return Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::InvalidArgument,
            ));
        }

        let state = self.lock_state()?;
        match &*state {
            ScreenVisionOutboundGrantStateSlot::Bound {
                grant,
                delivery_id: bound_delivery_id,
            } if grant.grant_id == grant_id => {
                if bound_delivery_id != delivery_id
                    || grant.candidate_id != candidate_id
                    || grant.life_id != life_id
                    || grant.screen_session_fence != screen_session_fence
                    || grant.outbound_policy_revision != outbound_policy_revision
                {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::DeliveryConflict,
                    ));
                }
                if &grant.destination_binding != destination_binding {
                    return Err(grant_error(
                        ScreenVisionOutboundGrantErrorCode::DestinationMismatch,
                    ));
                }
                Ok(grant_metadata(
                    grant,
                    ScreenVisionOutboundGrantState::Bound,
                    Instant::now(),
                ))
            }
            ScreenVisionOutboundGrantStateSlot::Consumed {
                grant,
                terminal_reason,
            } if grant.grant_id == grant_id => Err(terminal_error(*terminal_reason)),
            ScreenVisionOutboundGrantStateSlot::Bound { grant, .. }
                if grant.grant_id != grant_id =>
            {
                Err(grant_error(
                    ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                ))
            }
            _ => Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::GrantMismatch,
            )),
        }
    }

    fn retire_bound_exact(
        &self,
        grant_id: &str,
        delivery_id: &str,
        terminal_reason: ScreenVisionOutboundGrantTerminalReason,
    ) -> Result<(), ScreenVisionOutboundGrantError> {
        validate_id(grant_id)?;
        validate_id(delivery_id)?;

        #[cfg(test)]
        if self.terminal_retirement_failures.swap(0, Ordering::AcqRel) > 0 {
            return Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::SynchronizationUnavailable,
            ));
        }

        let mut state = self.lock_state()?;
        match &*state {
            ScreenVisionOutboundGrantStateSlot::Bound {
                grant,
                delivery_id: bound_delivery_id,
            } if grant.grant_id == grant_id && bound_delivery_id == delivery_id => {
                let grant =
                    match std::mem::replace(&mut *state, ScreenVisionOutboundGrantStateSlot::Empty)
                    {
                        ScreenVisionOutboundGrantStateSlot::Bound { grant, .. } => grant,
                        _ => unreachable!("grant state cannot change while its mutex is held"),
                    };
                *state = ScreenVisionOutboundGrantStateSlot::Consumed {
                    grant,
                    terminal_reason,
                };
                Ok(())
            }
            ScreenVisionOutboundGrantStateSlot::Bound { grant, .. }
                if grant.grant_id != grant_id =>
            {
                Err(grant_error(
                    ScreenVisionOutboundGrantErrorCode::GrantMismatch,
                ))
            }
            ScreenVisionOutboundGrantStateSlot::Bound { .. } => Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::DeliveryConflict,
            )),
            ScreenVisionOutboundGrantStateSlot::Consumed {
                grant,
                terminal_reason,
            } if grant.grant_id == grant_id => Err(terminal_error(*terminal_reason)),
            _ => Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::GrantMismatch,
            )),
        }
    }

    fn lock_state(
        &self,
    ) -> Result<MutexGuard<'_, ScreenVisionOutboundGrantStateSlot>, ScreenVisionOutboundGrantError>
    {
        self.state.lock().map_err(|_| {
            grant_error(ScreenVisionOutboundGrantErrorCode::SynchronizationUnavailable)
        })
    }
}

/// Composition boundary used by a future confirmation layer.  It accepts no
/// caller-supplied Life, fence, revision, candidate metadata, or enabled bit.
pub(crate) fn issue_user_confirmed_screen_vision_grant(
    grant_broker: &ScreenVisionOutboundGrantBroker,
    confirmation_event_id: &str,
    candidate_id: &str,
    destination_binding: ScreenVisionOutboundDestinationBinding,
    screen_repository: &dyn ScreenPerceptionRepository,
    session_gate: &ScreenPerceptionSessionGate,
    outbound_repository: &dyn ScreenVisionOutboundPolicyRepository,
    candidate_broker: &ScreenVisionOutboundCandidateBroker,
) -> Result<ScreenVisionOutboundGrantIssueOutcome, ScreenVisionOutboundGrantError> {
    grant_broker.issue_user_confirmed_screen_vision_grant(
        confirmation_event_id,
        candidate_id,
        destination_binding,
        screen_repository,
        session_gate,
        outbound_repository,
        candidate_broker,
    )
}

fn grant_error(code: ScreenVisionOutboundGrantErrorCode) -> ScreenVisionOutboundGrantError {
    ScreenVisionOutboundGrantError::new(code)
}

fn terminal_error(
    terminal_reason: ScreenVisionOutboundGrantTerminalReason,
) -> ScreenVisionOutboundGrantError {
    let code = match terminal_reason {
        ScreenVisionOutboundGrantTerminalReason::Expired => {
            ScreenVisionOutboundGrantErrorCode::GrantExpired
        }
        ScreenVisionOutboundGrantTerminalReason::Revoked
        | ScreenVisionOutboundGrantTerminalReason::Succeeded
        | ScreenVisionOutboundGrantTerminalReason::ProviderResponded
        | ScreenVisionOutboundGrantTerminalReason::Abandoned => {
            ScreenVisionOutboundGrantErrorCode::GrantConsumed
        }
    };
    grant_error(code)
}

fn validate_id(value: &str) -> Result<(), ScreenVisionOutboundGrantError> {
    if value.trim().is_empty() || value.chars().count() > MAX_ID_CHARACTERS {
        return Err(grant_error(
            ScreenVisionOutboundGrantErrorCode::InvalidArgument,
        ));
    }
    Ok(())
}

fn map_candidate_error(
    error: super::screen_vision_outbound_candidate::ScreenVisionOutboundCandidateError,
) -> ScreenVisionOutboundGrantError {
    let code = match error.code() {
        ScreenVisionOutboundCandidateErrorCode::SynchronizationUnavailable => {
            ScreenVisionOutboundGrantErrorCode::SynchronizationUnavailable
        }
        _ => ScreenVisionOutboundGrantErrorCode::CandidateUnavailable,
    };
    grant_error(code)
}

fn read_outbound_policy_revision(
    repository: &dyn ScreenVisionOutboundPolicyRepository,
    life_id: &str,
) -> Result<i64, ()> {
    let policy = repository
        .find_screen_vision_outbound_policy(life_id)
        .map_err(|_| ())?
        .ok_or(())?;
    validate_screen_vision_outbound_policy_state(&policy).map_err(|_| ())?;
    if policy.life_id != life_id || !policy.is_screen_vision_outbound_enabled() {
        return Err(());
    }
    Ok(policy.revision)
}

fn consume_ready_if_needed(state: &mut ScreenVisionOutboundGrantStateSlot, now: Instant) -> bool {
    let expired = match state {
        ScreenVisionOutboundGrantStateSlot::Ready(grant) => {
            now.saturating_duration_since(grant.created_at)
                >= SCREEN_VISION_OUTBOUND_READY_GRANT_TTL
        }
        ScreenVisionOutboundGrantStateSlot::Empty
        | ScreenVisionOutboundGrantStateSlot::Bound { .. }
        | ScreenVisionOutboundGrantStateSlot::Consumed { .. } => false,
    };
    if expired {
        let grant = match std::mem::replace(state, ScreenVisionOutboundGrantStateSlot::Empty) {
            ScreenVisionOutboundGrantStateSlot::Ready(grant) => grant,
            _ => unreachable!("READY state cannot change while its mutex is held"),
        };
        *state = ScreenVisionOutboundGrantStateSlot::Consumed {
            grant,
            terminal_reason: ScreenVisionOutboundGrantTerminalReason::Expired,
        };
    }
    expired
}

fn grant_metadata(
    grant: &ScreenVisionOutboundGrantRecord,
    state: ScreenVisionOutboundGrantState,
    now: Instant,
) -> ScreenVisionOutboundGrantMetadata {
    ScreenVisionOutboundGrantMetadata {
        grant_id: grant.grant_id.clone(),
        confirmation_event_id: grant.confirmation_event_id.clone(),
        candidate_id: grant.candidate_id.clone(),
        life_id: grant.life_id.clone(),
        outbound_policy_revision: grant.outbound_policy_revision,
        state,
        age: now.saturating_duration_since(grant.created_at),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perception::screen_capture::{ScreenFrame, ScreenPixelFormat};
    use crate::perception::screen_policy::{
        LifeScreenPerceptionPolicy, LifeScreenPerceptionPolicyCreateRequest,
        LifeScreenPerceptionPolicyEvent, LifeScreenPerceptionPolicyUpdateOutcome,
        LifeScreenPerceptionPolicyUpdateRequest, ScreenPerceptionCreateOutcome,
        ScreenPerceptionError, ScreenPerceptionRepository,
    };
    use crate::perception::screen_vision_outbound_destination::ScreenVisionOutboundDestinationProviderKind;
    use crate::perception::screen_vision_outbound_policy::{
        LifeScreenVisionOutboundPolicy, LifeScreenVisionOutboundPolicyCreateRequest,
        LifeScreenVisionOutboundPolicyEvent, LifeScreenVisionOutboundPolicyUpdateOutcome,
        LifeScreenVisionOutboundPolicyUpdateRequest, ScreenVisionOutboundPolicyCreateOutcome,
        ScreenVisionOutboundPolicyError, ScreenVisionOutboundPolicyRepository,
    };
    use crate::perception::screen_vision_outbound_projection::{
        project_screen_frame, ScreenVisionOutboundProjectionRequest, ScreenVisionOutboundRect,
    };
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const LIFE_A: &str = "life-a";
    const REVISION_A: i64 = 7;
    const PROFILE_ID_A: &str = "profile-a";
    const BASE_URL_A: &str = "https://vision.example.invalid/v1";
    const MODEL_NAME_A: &str = "vision-model-a";
    const PROFILE_UPDATED_AT_A: &str = "2026-08-31T00:00:00Z";

    #[derive(Clone)]
    struct FakeScreenPerceptionRepository {
        policy: Arc<Mutex<Option<LifeScreenPerceptionPolicy>>>,
    }

    impl FakeScreenPerceptionRepository {
        fn enabled_for(life_id: &str, enabled: bool) -> Self {
            Self {
                policy: Arc::new(Mutex::new(Some(LifeScreenPerceptionPolicy {
                    life_id: life_id.to_string(),
                    screen_perception_enabled: enabled,
                    revision: 1,
                    created_at: "2026-08-31T00:00:00Z".to_string(),
                    updated_at: "2026-08-31T00:00:00Z".to_string(),
                    policy_version:
                        crate::perception::screen_policy::SCREEN_PERCEPTION_POLICY_VERSION,
                }))),
            }
        }

        fn set_enabled(&self, enabled: bool) {
            let mut policy = self.policy.lock().expect("screen policy should lock");
            if let Some(current) = policy.as_mut() {
                current.screen_perception_enabled = enabled;
            }
        }
    }

    impl ScreenPerceptionRepository for FakeScreenPerceptionRepository {
        fn create_screen_perception_policy(
            &self,
            _request: LifeScreenPerceptionPolicyCreateRequest,
        ) -> Result<ScreenPerceptionCreateOutcome<LifeScreenPerceptionPolicy>, ScreenPerceptionError>
        {
            Err(ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicy>, ScreenPerceptionError> {
            Ok(self
                .policy
                .lock()
                .expect("screen policy should lock")
                .clone()
                .filter(|policy| policy.life_id == life_id))
        }

        fn update_screen_perception_policy(
            &self,
            _request: LifeScreenPerceptionPolicyUpdateRequest,
        ) -> Result<LifeScreenPerceptionPolicyUpdateOutcome, ScreenPerceptionError> {
            Err(ScreenPerceptionError::database())
        }

        fn find_screen_perception_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeScreenPerceptionPolicyEvent>, ScreenPerceptionError> {
            Ok(None)
        }
    }

    #[derive(Clone)]
    struct FakeScreenVisionOutboundPolicyRepository {
        policy: Arc<Mutex<Option<LifeScreenVisionOutboundPolicy>>>,
    }

    impl FakeScreenVisionOutboundPolicyRepository {
        fn enabled_for(life_id: &str, enabled: bool, revision: i64) -> Self {
            Self {
                policy: Arc::new(Mutex::new(Some(LifeScreenVisionOutboundPolicy {
                    life_id: life_id.to_string(),
                    screen_vision_outbound_enabled: enabled,
                    revision,
                    created_at: "2026-08-31T00:00:00Z".to_string(),
                    updated_at: "2026-08-31T00:00:00Z".to_string(),
                    policy_version:
                        crate::perception::screen_vision_outbound_policy::SCREEN_VISION_OUTBOUND_POLICY_VERSION,
                }))),
            }
        }

        fn set_policy(&self, enabled: bool, revision: i64) {
            let mut policy = self.policy.lock().expect("outbound policy should lock");
            *policy = Some(LifeScreenVisionOutboundPolicy {
                life_id: LIFE_A.to_string(),
                screen_vision_outbound_enabled: enabled,
                revision,
                created_at: "2026-08-31T00:00:00Z".to_string(),
                updated_at: "2026-08-31T00:00:00Z".to_string(),
                policy_version:
                    crate::perception::screen_vision_outbound_policy::SCREEN_VISION_OUTBOUND_POLICY_VERSION,
            });
        }

        fn set_raw(&self, policy: Option<LifeScreenVisionOutboundPolicy>) {
            *self.policy.lock().expect("outbound policy should lock") = policy;
        }
    }

    impl ScreenVisionOutboundPolicyRepository for FakeScreenVisionOutboundPolicyRepository {
        fn create_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyCreateRequest,
        ) -> Result<
            ScreenVisionOutboundPolicyCreateOutcome<LifeScreenVisionOutboundPolicy>,
            ScreenVisionOutboundPolicyError,
        > {
            Err(ScreenVisionOutboundPolicyError::database())
        }

        fn find_screen_vision_outbound_policy(
            &self,
            life_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicy>, ScreenVisionOutboundPolicyError>
        {
            Ok(self
                .policy
                .lock()
                .expect("outbound policy should lock")
                .clone()
                .filter(|policy| policy.life_id == life_id))
        }

        fn update_screen_vision_outbound_policy(
            &self,
            _request: LifeScreenVisionOutboundPolicyUpdateRequest,
        ) -> Result<LifeScreenVisionOutboundPolicyUpdateOutcome, ScreenVisionOutboundPolicyError>
        {
            Err(ScreenVisionOutboundPolicyError::database())
        }

        fn find_screen_vision_outbound_policy_event(
            &self,
            _life_id: &str,
            _event_id: &str,
        ) -> Result<Option<LifeScreenVisionOutboundPolicyEvent>, ScreenVisionOutboundPolicyError>
        {
            Ok(None)
        }
    }

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
            let mut now = self.now.lock().expect("manual clock should lock");
            *now = now
                .checked_add(duration)
                .expect("manual clock should remain representable");
        }
    }

    impl GrantClock for ManualClock {
        fn now(&self) -> Instant {
            *self.now.lock().expect("manual clock should lock")
        }
    }

    struct ScriptedGrantIdSource {
        outputs: Mutex<Vec<Result<String, ScreenVisionOutboundGrantError>>>,
    }

    impl ScriptedGrantIdSource {
        fn new(outputs: Vec<Result<String, ScreenVisionOutboundGrantError>>) -> Self {
            Self {
                outputs: Mutex::new(outputs),
            }
        }

        fn remaining(&self) -> usize {
            self.outputs
                .lock()
                .expect("grant id source should lock")
                .len()
        }
    }

    impl GrantIdSource for ScriptedGrantIdSource {
        fn generate(&self) -> Result<String, ScreenVisionOutboundGrantError> {
            let mut outputs = self.outputs.lock().expect("grant id source should lock");
            if outputs.is_empty() {
                return Err(grant_error(
                    ScreenVisionOutboundGrantErrorCode::RandomUnavailable,
                ));
            }
            outputs.remove(0)
        }
    }

    struct Fixture {
        screen_repository: FakeScreenPerceptionRepository,
        outbound_repository: FakeScreenVisionOutboundPolicyRepository,
        session_gate: ScreenPerceptionSessionGate,
        candidate_broker: ScreenVisionOutboundCandidateBroker,
        grant_broker: ScreenVisionOutboundGrantBroker,
        candidate_id: String,
    }

    impl Fixture {
        fn new() -> Self {
            Self::with_grant_broker(ScreenVisionOutboundGrantBroker::new())
        }

        fn with_grant_broker(grant_broker: ScreenVisionOutboundGrantBroker) -> Self {
            let screen_repository = FakeScreenPerceptionRepository::enabled_for(LIFE_A, true);
            let outbound_repository =
                FakeScreenVisionOutboundPolicyRepository::enabled_for(LIFE_A, true, REVISION_A);
            let session_gate = ScreenPerceptionSessionGate::new();
            session_gate.arm_for_life(LIFE_A);
            let candidate_broker = ScreenVisionOutboundCandidateBroker::new();
            let screen_session_fence = session_gate
                .life_fence_for(LIFE_A)
                .expect("test session should be armed")
                .to_string();
            let candidate_id = candidate_broker
                .replace_candidate(LIFE_A, &screen_session_fence, REVISION_A, projection())
                .expect("test candidate should install");
            Self {
                screen_repository,
                outbound_repository,
                session_gate,
                candidate_broker,
                grant_broker,
                candidate_id,
            }
        }

        fn issue(
            &self,
            confirmation_event_id: &str,
            destination_binding: ScreenVisionOutboundDestinationBinding,
        ) -> Result<ScreenVisionOutboundGrantIssueOutcome, ScreenVisionOutboundGrantError> {
            self.issue_with(
                confirmation_event_id,
                &self.candidate_id,
                destination_binding,
            )
        }

        fn issue_with(
            &self,
            confirmation_event_id: &str,
            candidate_id: &str,
            destination_binding: ScreenVisionOutboundDestinationBinding,
        ) -> Result<ScreenVisionOutboundGrantIssueOutcome, ScreenVisionOutboundGrantError> {
            issue_user_confirmed_screen_vision_grant(
                &self.grant_broker,
                confirmation_event_id,
                candidate_id,
                destination_binding,
                &self.screen_repository,
                &self.session_gate,
                &self.outbound_repository,
                &self.candidate_broker,
            )
        }
    }

    fn projection(
    ) -> crate::perception::screen_vision_outbound_projection::ScreenVisionOutboundProjection {
        let frame = ScreenFrame {
            width: 1,
            height: 1,
            pixel_format: ScreenPixelFormat::Bgra8,
            bytes: vec![3, 2, 1, 255],
        };
        let request = ScreenVisionOutboundProjectionRequest::new(
            ScreenVisionOutboundRect::new(0, 0, 1, 1),
            Vec::new(),
        );
        project_screen_frame(&frame, &request).expect("test projection should succeed")
    }

    fn destination() -> ScreenVisionOutboundDestinationBinding {
        destination_with(PROFILE_ID_A, BASE_URL_A, MODEL_NAME_A, PROFILE_UPDATED_AT_A)
    }

    fn destination_with(
        profile_id: &str,
        base_url: &str,
        model_name: &str,
        profile_updated_at: &str,
    ) -> ScreenVisionOutboundDestinationBinding {
        ScreenVisionOutboundDestinationBinding::new(
            profile_id.to_string(),
            ScreenVisionOutboundDestinationProviderKind::OpenaiCompatible,
            base_url.to_string(),
            model_name.to_string(),
            profile_updated_at.to_string(),
        )
        .expect("test destination should be valid")
    }

    fn issue_metadata(
        outcome: ScreenVisionOutboundGrantIssueOutcome,
    ) -> ScreenVisionOutboundGrantMetadata {
        match outcome {
            ScreenVisionOutboundGrantIssueOutcome::Issued(metadata)
            | ScreenVisionOutboundGrantIssueOutcome::Replayed(metadata) => metadata,
        }
    }

    fn claim_metadata(
        outcome: ScreenVisionOutboundGrantClaimOutcome,
    ) -> ScreenVisionOutboundGrantMetadata {
        match outcome {
            ScreenVisionOutboundGrantClaimOutcome::Claimed(metadata)
            | ScreenVisionOutboundGrantClaimOutcome::Replayed(metadata) => metadata,
        }
    }

    fn assert_error_code<T>(
        result: Result<T, ScreenVisionOutboundGrantError>,
        expected: ScreenVisionOutboundGrantErrorCode,
    ) {
        match result {
            Ok(_) => panic!("operation should fail"),
            Err(error) => assert_eq!(error.code(), expected),
        }
    }

    #[test]
    fn fresh_slot_and_input_validation_are_fail_closed() {
        let fixture = Fixture::new();

        assert_error_code(
            fixture.grant_broker.get_exact("grant"),
            ScreenVisionOutboundGrantErrorCode::GrantMismatch,
        );
        assert_error_code(
            fixture.issue("", destination()),
            ScreenVisionOutboundGrantErrorCode::InvalidArgument,
        );
        assert_error_code(
            fixture.issue_with("event-a", "", destination()),
            ScreenVisionOutboundGrantErrorCode::InvalidArgument,
        );
        assert_error_code(
            fixture.grant_broker.get_exact(""),
            ScreenVisionOutboundGrantErrorCode::InvalidArgument,
        );
    }

    #[test]
    fn missing_expired_and_replaced_candidates_are_unavailable() {
        let fixture = Fixture::new();
        assert_error_code(
            fixture.issue_with("event-missing", "missing-candidate", destination()),
            ScreenVisionOutboundGrantErrorCode::CandidateUnavailable,
        );

        let expired_fixture = Fixture::new();
        expired_fixture.candidate_broker.expire_current_for_test();
        assert_error_code(
            expired_fixture.issue("event-expired", destination()),
            ScreenVisionOutboundGrantErrorCode::CandidateUnavailable,
        );

        let replaced_fixture = Fixture::new();
        let old_candidate_id = replaced_fixture.candidate_id.clone();
        let fence = replaced_fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("test session should be armed")
            .to_string();
        replaced_fixture
            .candidate_broker
            .replace_candidate(LIFE_A, &fence, REVISION_A, projection())
            .expect("replacement candidate should install");
        assert_error_code(
            replaced_fixture.issue_with("event-replaced", &old_candidate_id, destination()),
            ScreenVisionOutboundGrantErrorCode::CandidateUnavailable,
        );
    }

    #[test]
    fn d23_authority_and_session_fence_are_rechecked() {
        let disabled_fixture = Fixture::new();
        disabled_fixture.screen_repository.set_enabled(false);
        assert_error_code(
            disabled_fixture.issue("event-disabled", destination()),
            ScreenVisionOutboundGrantErrorCode::LocalScreenAuthorityUnavailable,
        );

        let disarmed_fixture = Fixture::new();
        disarmed_fixture.session_gate.disarm();
        assert_error_code(
            disarmed_fixture.issue("event-disarmed", destination()),
            ScreenVisionOutboundGrantErrorCode::LocalScreenAuthorityUnavailable,
        );

        let rearmed_fixture = Fixture::new();
        rearmed_fixture.session_gate.disarm();
        rearmed_fixture.session_gate.arm_for_life(LIFE_A);
        assert_error_code(
            rearmed_fixture.issue("event-rearmed", destination()),
            ScreenVisionOutboundGrantErrorCode::SessionFenceMismatch,
        );
    }

    #[test]
    fn d25_policy_enablement_revision_and_persisted_state_are_rechecked() {
        let disabled_fixture = Fixture::new();
        disabled_fixture
            .outbound_repository
            .set_policy(false, REVISION_A);
        assert_error_code(
            disabled_fixture.issue("event-policy-disabled", destination()),
            ScreenVisionOutboundGrantErrorCode::OutboundPolicyUnavailable,
        );

        let revision_fixture = Fixture::new();
        revision_fixture
            .outbound_repository
            .set_policy(true, REVISION_A + 1);
        assert_error_code(
            revision_fixture.issue("event-revision", destination()),
            ScreenVisionOutboundGrantErrorCode::OutboundPolicyMismatch,
        );

        let aba_fixture = Fixture::new();
        aba_fixture
            .outbound_repository
            .set_policy(false, REVISION_A + 1);
        aba_fixture
            .outbound_repository
            .set_policy(true, REVISION_A + 2);
        assert_error_code(
            aba_fixture.issue("event-aba", destination()),
            ScreenVisionOutboundGrantErrorCode::OutboundPolicyMismatch,
        );

        let malformed_fixture = Fixture::new();
        malformed_fixture
            .outbound_repository
            .set_raw(Some(LifeScreenVisionOutboundPolicy {
                life_id: LIFE_A.to_string(),
                screen_vision_outbound_enabled: true,
                revision: 0,
                created_at: "2026-08-31T00:00:00Z".to_string(),
                updated_at: "2026-08-31T00:00:00Z".to_string(),
                policy_version:
                    crate::perception::screen_vision_outbound_policy::SCREEN_VISION_OUTBOUND_POLICY_VERSION,
            }));
        assert_error_code(
            malformed_fixture.issue("event-malformed", destination()),
            ScreenVisionOutboundGrantErrorCode::OutboundPolicyUnavailable,
        );
    }

    #[test]
    fn valid_issue_derives_exact_candidate_scope_and_moves_full_destination_binding_inside() {
        let fixture = Fixture::new();
        let binding = destination();
        let metadata = issue_metadata(
            fixture
                .issue("event-valid", destination())
                .expect("valid issue should succeed"),
        );

        assert_eq!(metadata.confirmation_event_id, "event-valid");
        assert_eq!(metadata.candidate_id, fixture.candidate_id);
        assert_eq!(metadata.life_id, LIFE_A);
        assert_eq!(metadata.outbound_policy_revision, REVISION_A);
        assert_eq!(metadata.state, ScreenVisionOutboundGrantState::Ready);
        assert_eq!(metadata.age, Duration::ZERO);

        let state = fixture
            .grant_broker
            .state
            .lock()
            .expect("grant state should lock");
        match &*state {
            ScreenVisionOutboundGrantStateSlot::Ready(grant) => {
                assert_eq!(grant.grant_id, metadata.grant_id);
                assert_eq!(grant.candidate_id, fixture.candidate_id);
                assert_eq!(grant.life_id, LIFE_A);
                assert_eq!(grant.screen_session_fence, "1");
                assert_eq!(grant.outbound_policy_revision, REVISION_A);
                assert!(grant.destination_binding == binding);
            }
            _ => panic!("valid issue should leave READY state"),
        }
    }

    #[test]
    fn fresh_grant_id_is_separate_128_bit_lowercase_hex_and_metadata_is_bounded() {
        let fixture = Fixture::new();
        let metadata = issue_metadata(
            fixture
                .issue("event-id", destination())
                .expect("valid issue should succeed"),
        );

        assert_eq!(metadata.grant_id.len(), GRANT_ID_HEX_LENGTH);
        assert!(metadata
            .grant_id
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
        assert!(!metadata.grant_id.contains(LIFE_A));
        assert!(!metadata.grant_id.contains(&fixture.candidate_id));
    }

    #[test]
    fn confirmation_event_replay_conflict_and_unused_replacement_are_exact() {
        let replay_fixture = Fixture::new();
        let first = issue_metadata(
            replay_fixture
                .issue("event-replay", destination())
                .expect("initial issue should succeed"),
        );
        let replayed = replay_fixture
            .issue("event-replay", destination())
            .expect("same exact evidence should replay");
        let replayed = issue_metadata(replayed);
        assert_eq!(replayed.grant_id, first.grant_id);
        assert_eq!(replayed.state, ScreenVisionOutboundGrantState::Ready);

        let candidate_conflict_fixture = Fixture::new();
        let original = issue_metadata(
            candidate_conflict_fixture
                .issue("event-conflict", destination())
                .expect("initial issue should succeed"),
        );
        let fence = candidate_conflict_fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("test session should be armed")
            .to_string();
        let replacement_candidate = candidate_conflict_fixture
            .candidate_broker
            .replace_candidate(LIFE_A, &fence, REVISION_A, projection())
            .expect("replacement candidate should install");
        assert_error_code(
            candidate_conflict_fixture.issue_with(
                "event-conflict",
                &replacement_candidate,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::ConfirmationEventConflict,
        );
        let preserved = candidate_conflict_fixture
            .grant_broker
            .get_exact(&original.grant_id)
            .expect("conflicting issue must preserve READY");
        assert_eq!(preserved.candidate_id, original.candidate_id);

        let destination_conflict_fixture = Fixture::new();
        let original = issue_metadata(
            destination_conflict_fixture
                .issue("event-destination-conflict", destination())
                .expect("initial issue should succeed"),
        );
        assert_error_code(
            destination_conflict_fixture.issue(
                "event-destination-conflict",
                destination_with("profile-b", BASE_URL_A, MODEL_NAME_A, PROFILE_UPDATED_AT_A),
            ),
            ScreenVisionOutboundGrantErrorCode::ConfirmationEventConflict,
        );
        assert_eq!(
            destination_conflict_fixture
                .grant_broker
                .get_exact(&original.grant_id)
                .expect("conflicting destination must preserve READY")
                .grant_id,
            original.grant_id
        );

        let replace_fixture = Fixture::new();
        let old = issue_metadata(
            replace_fixture
                .issue("event-old", destination())
                .expect("initial issue should succeed"),
        );
        assert_error_code(
            replace_fixture.issue("event-new", destination()),
            ScreenVisionOutboundGrantErrorCode::GrantInUse,
        );
        let replayed = issue_metadata(
            replace_fixture
                .issue("event-old", destination())
                .expect("same READY evidence should replay"),
        );
        assert_eq!(old.grant_id, replayed.grant_id);
        assert_eq!(
            replace_fixture
                .grant_broker
                .get_exact(&old.grant_id)
                .expect("original READY should remain live")
                .grant_id,
            old.grant_id
        );
    }

    #[test]
    fn bound_grant_cannot_be_replaced_and_random_or_sync_failures_preserve_state() {
        let bound_fixture = Fixture::new();
        let bound = issue_metadata(
            bound_fixture
                .issue("event-bound", destination())
                .expect("initial issue should succeed"),
        );
        let claim = bound_fixture
            .grant_broker
            .claim_exact_for_delivery(
                &bound.grant_id,
                "delivery-bound",
                &bound_fixture.candidate_id,
                destination(),
            )
            .expect("exact claim should succeed");
        assert_eq!(
            claim_metadata(claim).state,
            ScreenVisionOutboundGrantState::Bound
        );
        assert_error_code(
            bound_fixture.issue("event-replacement", destination()),
            ScreenVisionOutboundGrantErrorCode::GrantInUse,
        );
        let bound_replacement_fence = bound_fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("test session should be armed")
            .to_string();
        let bound_replacement_candidate = bound_fixture
            .candidate_broker
            .replace_candidate(LIFE_A, &bound_replacement_fence, REVISION_A, projection())
            .expect("replacement candidate should install");
        assert_error_code(
            bound_fixture.issue_with(
                "event-replacement-new-candidate",
                &bound_replacement_candidate,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::GrantInUse,
        );
        assert_eq!(
            bound_fixture
                .grant_broker
                .get_exact(&bound.grant_id)
                .expect("BOUND must survive replacement attempt")
                .state,
            ScreenVisionOutboundGrantState::Bound
        );

        let first_id = "a".repeat(GRANT_ID_HEX_LENGTH);
        let clock = ManualClock::new();
        let scripted_source = Arc::new(ScriptedGrantIdSource::new(vec![
            Ok(first_id.clone()),
            Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::RandomUnavailable,
            )),
        ]));
        let scripted_broker = ScreenVisionOutboundGrantBroker::with_clock_and_id_source(
            Arc::new(clock),
            scripted_source,
        );
        let random_fixture = Fixture::with_grant_broker(scripted_broker);
        let issued = issue_metadata(
            random_fixture
                .issue("event-random-first", destination())
                .expect("scripted first ID should issue"),
        );
        assert_eq!(issued.grant_id, first_id);
        let replacement_fence = random_fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("test session should be armed")
            .to_string();
        let replacement_candidate = random_fixture
            .candidate_broker
            .replace_candidate(LIFE_A, &replacement_fence, REVISION_A, projection())
            .expect("replacement candidate should install");
        assert_error_code(
            random_fixture.issue_with("event-random-second", &replacement_candidate, destination()),
            ScreenVisionOutboundGrantErrorCode::RandomUnavailable,
        );
        assert_eq!(
            random_fixture
                .grant_broker
                .get_exact(&first_id)
                .expect("random failure must preserve READY")
                .grant_id,
            first_id
        );

        let consumed_first_id = "c".repeat(GRANT_ID_HEX_LENGTH);
        let consumed_clock = ManualClock::new();
        let consumed_source = ScriptedGrantIdSource::new(vec![
            Ok(consumed_first_id.clone()),
            Err(grant_error(
                ScreenVisionOutboundGrantErrorCode::RandomUnavailable,
            )),
        ]);
        let consumed_broker = ScreenVisionOutboundGrantBroker::with_clock_and_id_source(
            Arc::new(consumed_clock),
            Arc::new(consumed_source),
        );
        let consumed_fixture = Fixture::with_grant_broker(consumed_broker);
        let consumed = issue_metadata(
            consumed_fixture
                .issue("event-random-consumed-first", destination())
                .expect("scripted consumed issue should succeed"),
        );
        consumed_fixture
            .grant_broker
            .revoke_ready_exact(&consumed.grant_id)
            .expect("READY should become consumed");
        let consumed_replacement_fence = consumed_fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("test session should be armed")
            .to_string();
        let consumed_replacement_candidate = consumed_fixture
            .candidate_broker
            .replace_candidate(
                LIFE_A,
                &consumed_replacement_fence,
                REVISION_A,
                projection(),
            )
            .expect("replacement candidate should install");
        assert_error_code(
            consumed_fixture.issue_with(
                "event-random-consumed-second",
                &consumed_replacement_candidate,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::RandomUnavailable,
        );
        assert_error_code(
            consumed_fixture.grant_broker.get_exact(&consumed_first_id),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );

        let sync_fixture = Fixture::new();
        let issued = issue_metadata(
            sync_fixture
                .issue("event-sync-first", destination())
                .expect("initial issue should succeed"),
        );
        let poisoned = catch_unwind(AssertUnwindSafe(|| {
            let _state = sync_fixture
                .grant_broker
                .state
                .lock()
                .expect("grant state should initially lock");
            panic!("intentional test mutex poison");
        }));
        assert!(poisoned.is_err());
        assert_error_code(
            sync_fixture.issue("event-sync-second", destination()),
            ScreenVisionOutboundGrantErrorCode::SynchronizationUnavailable,
        );
        sync_fixture.grant_broker.state.clear_poison();
        assert_eq!(
            sync_fixture
                .grant_broker
                .get_exact(&issued.grant_id)
                .expect("sync failure must preserve READY")
                .grant_id,
            issued.grant_id
        );

        let candidate_sync_fixture = Fixture::new();
        let issued = issue_metadata(
            candidate_sync_fixture
                .issue("event-candidate-sync-first", destination())
                .expect("initial issue should succeed"),
        );
        candidate_sync_fixture.candidate_broker.poison_for_test();
        assert_error_code(
            candidate_sync_fixture.issue("event-candidate-sync-second", destination()),
            ScreenVisionOutboundGrantErrorCode::SynchronizationUnavailable,
        );
        candidate_sync_fixture
            .candidate_broker
            .clear_poison_for_test();
        assert_eq!(
            candidate_sync_fixture
                .grant_broker
                .get_exact(&issued.grant_id)
                .expect("candidate sync failure must preserve READY")
                .grant_id,
            issued.grant_id
        );
    }

    #[test]
    fn ready_ttl_is_exact_non_refreshing_and_bound_is_not_auto_expired() {
        let ready_clock = ManualClock::new();
        let ready_broker = ScreenVisionOutboundGrantBroker::with_clock_and_id_source(
            Arc::new(ready_clock.clone()),
            Arc::new(CsprngGrantIdSource),
        );
        let ready_fixture = Fixture::with_grant_broker(ready_broker);
        let ready = issue_metadata(
            ready_fixture
                .issue("event-ttl", destination())
                .expect("initial issue should succeed"),
        );
        ready_clock.advance(SCREEN_VISION_OUTBOUND_READY_GRANT_TTL - Duration::from_secs(1));
        assert_eq!(
            ready_fixture
                .grant_broker
                .get_exact(&ready.grant_id)
                .expect("READY should live one second before TTL")
                .state,
            ScreenVisionOutboundGrantState::Ready
        );
        ready_clock.advance(Duration::from_secs(1));
        assert_error_code(
            ready_fixture.grant_broker.get_exact(&ready.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantExpired,
        );
        assert_error_code(
            ready_fixture.grant_broker.get_exact(&ready.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantExpired,
        );

        let read_clock = ManualClock::new();
        let read_broker = ScreenVisionOutboundGrantBroker::with_clock_and_id_source(
            Arc::new(read_clock.clone()),
            Arc::new(CsprngGrantIdSource),
        );
        let read_fixture = Fixture::with_grant_broker(read_broker);
        let read_once = issue_metadata(
            read_fixture
                .issue("event-no-refresh", destination())
                .expect("initial issue should succeed"),
        );
        read_clock.advance(Duration::from_secs(60));
        let _ = read_fixture
            .grant_broker
            .get_exact(&read_once.grant_id)
            .expect("intermediate read should succeed");
        read_clock.advance(Duration::from_secs(61));
        assert_error_code(
            read_fixture.grant_broker.get_exact(&read_once.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantExpired,
        );

        let bound_clock = ManualClock::new();
        let bound_broker = ScreenVisionOutboundGrantBroker::with_clock_and_id_source(
            Arc::new(bound_clock.clone()),
            Arc::new(CsprngGrantIdSource),
        );
        let bound_fixture = Fixture::with_grant_broker(bound_broker);
        let bound = issue_metadata(
            bound_fixture
                .issue("event-bound-ttl", destination())
                .expect("initial issue should succeed"),
        );
        bound_fixture
            .grant_broker
            .claim_exact_for_delivery(
                &bound.grant_id,
                "delivery-ttl",
                &bound_fixture.candidate_id,
                destination(),
            )
            .expect("exact claim should succeed");
        bound_clock.advance(SCREEN_VISION_OUTBOUND_READY_GRANT_TTL + Duration::from_secs(1));
        assert_eq!(
            bound_fixture
                .grant_broker
                .get_exact(&bound.grant_id)
                .expect("BOUND must not expire by READY TTL")
                .state,
            ScreenVisionOutboundGrantState::Bound
        );
        bound_fixture
            .grant_broker
            .retire_bound_after_success(&bound.grant_id, "delivery-ttl")
            .expect("exact bound retirement should succeed");
    }

    #[test]
    fn exact_claim_retry_and_conflicts_preserve_one_bound_owner() {
        let fixture = Fixture::new();
        let issued = issue_metadata(
            fixture
                .issue("event-claim", destination())
                .expect("initial issue should succeed"),
        );
        let claimed = fixture
            .grant_broker
            .claim_exact_for_delivery(
                &issued.grant_id,
                "delivery-a",
                &fixture.candidate_id,
                destination(),
            )
            .expect("exact claim should succeed");
        let claimed = claim_metadata(claimed);
        assert_eq!(claimed.grant_id, issued.grant_id);
        assert_eq!(claimed.state, ScreenVisionOutboundGrantState::Bound);

        let replayed = fixture
            .grant_broker
            .claim_exact_for_delivery(
                &issued.grant_id,
                "delivery-a",
                &fixture.candidate_id,
                destination(),
            )
            .expect("same delivery retry should replay");
        assert_eq!(claim_metadata(replayed).grant_id, issued.grant_id);
        assert_error_code(
            fixture.grant_broker.claim_exact_for_delivery(
                &issued.grant_id,
                "delivery-b",
                &fixture.candidate_id,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::DeliveryConflict,
        );
        assert_error_code(
            fixture.grant_broker.claim_exact_for_delivery(
                "wrong-grant",
                "delivery-a",
                &fixture.candidate_id,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::GrantMismatch,
        );
        assert_error_code(
            fixture.grant_broker.claim_exact_for_delivery(
                &issued.grant_id,
                "delivery-a",
                "wrong-candidate",
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::GrantMismatch,
        );
        assert_eq!(
            fixture
                .grant_broker
                .get_exact(&issued.grant_id)
                .expect("conflicts must preserve BOUND")
                .state,
            ScreenVisionOutboundGrantState::Bound
        );
    }

    #[test]
    fn every_destination_dimension_is_bound_exactly_for_claim() {
        let changed_destinations = [
            destination_with("profile-b", BASE_URL_A, MODEL_NAME_A, PROFILE_UPDATED_AT_A),
            destination_with(
                PROFILE_ID_A,
                "https://vision.example.invalid/v2",
                MODEL_NAME_A,
                PROFILE_UPDATED_AT_A,
            ),
            destination_with(
                PROFILE_ID_A,
                BASE_URL_A,
                "vision-model-b",
                PROFILE_UPDATED_AT_A,
            ),
            destination_with(
                PROFILE_ID_A,
                BASE_URL_A,
                MODEL_NAME_A,
                "2026-09-01T00:00:00Z",
            ),
        ];

        for changed_destination in changed_destinations {
            let fixture = Fixture::new();
            let issued = issue_metadata(
                fixture
                    .issue("event-destination", destination())
                    .expect("initial issue should succeed"),
            );
            assert_error_code(
                fixture.grant_broker.claim_exact_for_delivery(
                    &issued.grant_id,
                    "delivery-destination",
                    &fixture.candidate_id,
                    changed_destination,
                ),
                ScreenVisionOutboundGrantErrorCode::DestinationMismatch,
            );
            assert_eq!(
                fixture
                    .grant_broker
                    .get_exact(&issued.grant_id)
                    .expect("destination mismatch must preserve READY")
                    .state,
                ScreenVisionOutboundGrantState::Ready
            );
        }
    }

    #[test]
    fn exact_retirement_consumes_bound_state_and_stale_cleanup_cannot_touch_newer_state() {
        let fixture = Fixture::new();
        let first = issue_metadata(
            fixture
                .issue("event-retire", destination())
                .expect("initial issue should succeed"),
        );
        fixture
            .grant_broker
            .claim_exact_for_delivery(
                &first.grant_id,
                "delivery-retire",
                &fixture.candidate_id,
                destination(),
            )
            .expect("exact claim should succeed");
        assert_error_code(
            fixture
                .grant_broker
                .retire_bound_after_success(&first.grant_id, "wrong-delivery"),
            ScreenVisionOutboundGrantErrorCode::DeliveryConflict,
        );
        assert_eq!(
            fixture
                .grant_broker
                .get_exact(&first.grant_id)
                .expect("wrong retirement must preserve BOUND")
                .state,
            ScreenVisionOutboundGrantState::Bound
        );
        fixture
            .grant_broker
            .retire_bound_after_success(&first.grant_id, "delivery-retire")
            .expect("exact retirement should clear BOUND");
        assert_error_code(
            fixture.grant_broker.get_exact(&first.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );

        let ready_fixture = Fixture::new();
        let old_ready = issue_metadata(
            ready_fixture
                .issue("event-ready-old", destination())
                .expect("initial issue should succeed"),
        );
        let ready_replacement_fence = ready_fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("test session should be armed")
            .to_string();
        let ready_replacement_candidate = ready_fixture
            .candidate_broker
            .replace_candidate(LIFE_A, &ready_replacement_fence, REVISION_A, projection())
            .expect("replacement candidate should install");
        let new_ready = issue_metadata(
            ready_fixture
                .issue_with(
                    "event-ready-new",
                    &ready_replacement_candidate,
                    destination(),
                )
                .expect("new candidate should replace READY"),
        );
        assert_error_code(
            ready_fixture
                .grant_broker
                .revoke_ready_exact(&old_ready.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantMismatch,
        );
        assert_eq!(
            ready_fixture
                .grant_broker
                .get_exact(&new_ready.grant_id)
                .expect("stale revoke must preserve newer READY")
                .grant_id,
            new_ready.grant_id
        );

        let stale_bound_fixture = Fixture::new();
        let old_bound = issue_metadata(
            stale_bound_fixture
                .issue("event-bound-old", destination())
                .expect("initial issue should succeed"),
        );
        stale_bound_fixture
            .grant_broker
            .claim_exact_for_delivery(
                &old_bound.grant_id,
                "delivery-old",
                &stale_bound_fixture.candidate_id,
                destination(),
            )
            .expect("exact claim should succeed");
        stale_bound_fixture
            .grant_broker
            .retire_bound_after_success(&old_bound.grant_id, "delivery-old")
            .expect("old bound state should retire");
        let replacement_fence = stale_bound_fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("test session should be armed")
            .to_string();
        let replacement_candidate = stale_bound_fixture
            .candidate_broker
            .replace_candidate(LIFE_A, &replacement_fence, REVISION_A, projection())
            .expect("replacement candidate should install");
        let new_ready = issue_metadata(
            stale_bound_fixture
                .issue_with("event-bound-new", &replacement_candidate, destination())
                .expect("new READY should issue"),
        );
        assert_error_code(
            stale_bound_fixture
                .grant_broker
                .retire_bound_after_success(&old_bound.grant_id, "delivery-old"),
            ScreenVisionOutboundGrantErrorCode::GrantMismatch,
        );
        assert_eq!(
            stale_bound_fixture
                .grant_broker
                .get_exact(&new_ready.grant_id)
                .expect("stale retirement must preserve newer READY")
                .grant_id,
            new_ready.grant_id
        );
    }

    #[test]
    fn expired_confirmation_is_consumed_without_a_second_id_generation() {
        let first_id = "a".repeat(GRANT_ID_HEX_LENGTH);
        let second_id = "b".repeat(GRANT_ID_HEX_LENGTH);
        let clock = ManualClock::new();
        let id_source = Arc::new(ScriptedGrantIdSource::new(vec![
            Ok(first_id.clone()),
            Ok(second_id),
        ]));
        let broker = ScreenVisionOutboundGrantBroker::with_clock_and_id_source(
            Arc::new(clock.clone()),
            id_source.clone(),
        );
        let fixture = Fixture::with_grant_broker(broker);
        let first = issue_metadata(
            fixture
                .issue("event-expiring", destination())
                .expect("initial issue should succeed"),
        );
        clock.advance(SCREEN_VISION_OUTBOUND_READY_GRANT_TTL);

        assert_error_code(
            fixture.issue("event-expiring", destination()),
            ScreenVisionOutboundGrantErrorCode::GrantExpired,
        );
        assert_eq!(id_source.remaining(), 1);
        assert_error_code(
            fixture.grant_broker.get_exact(&first.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantExpired,
        );
        assert_error_code(
            fixture.grant_broker.claim_exact_for_delivery(
                &first.grant_id,
                "delivery-expired",
                &fixture.candidate_id,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::GrantExpired,
        );
    }

    #[test]
    fn successful_delivery_consumes_confirmation_and_candidate() {
        let fixture = Fixture::new();
        let issued = issue_metadata(
            fixture
                .issue("event-success", destination())
                .expect("initial issue should succeed"),
        );
        fixture
            .grant_broker
            .claim_exact_for_delivery(
                &issued.grant_id,
                "delivery-success",
                &fixture.candidate_id,
                destination(),
            )
            .expect("exact claim should succeed");
        fixture
            .grant_broker
            .retire_bound_after_success(&issued.grant_id, "delivery-success")
            .expect("exact success retirement should succeed");

        assert_error_code(
            fixture.grant_broker.get_exact(&issued.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );
        assert_error_code(
            fixture.issue("event-success", destination()),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );
        assert_error_code(
            fixture.grant_broker.claim_exact_for_delivery(
                &issued.grant_id,
                "delivery-success",
                &fixture.candidate_id,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );
    }

    #[test]
    fn provider_response_and_user_abandon_are_terminal_exact_bound_settlements() {
        let provider_fixture = Fixture::new();
        let provider = issue_metadata(
            provider_fixture
                .issue("event-provider-response", destination())
                .expect("provider-response grant should issue"),
        );
        provider_fixture
            .grant_broker
            .claim_exact_for_delivery(
                &provider.grant_id,
                "delivery-provider-response",
                &provider_fixture.candidate_id,
                destination(),
            )
            .expect("provider-response grant should bind");
        provider_fixture
            .grant_broker
            .retire_bound_after_provider_response(&provider.grant_id, "delivery-provider-response")
            .expect("provider response should consume exact BOUND");
        assert_error_code(
            provider_fixture.grant_broker.claim_exact_for_delivery(
                &provider.grant_id,
                "delivery-provider-response",
                &provider_fixture.candidate_id,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );

        let abandon_fixture = Fixture::new();
        let abandoned = issue_metadata(
            abandon_fixture
                .issue("event-abandon", destination())
                .expect("abandon grant should issue"),
        );
        abandon_fixture
            .grant_broker
            .claim_exact_for_delivery(
                &abandoned.grant_id,
                "delivery-abandon",
                &abandon_fixture.candidate_id,
                destination(),
            )
            .expect("abandon grant should bind");
        abandon_fixture
            .grant_broker
            .abandon_bound_exact(&abandoned.grant_id, "delivery-abandon")
            .expect("idle exact BOUND should be abandonable");
        assert_error_code(
            abandon_fixture.issue("event-abandon", destination()),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );
        assert_error_code(
            abandon_fixture.issue("event-new-same-candidate", destination()),
            ScreenVisionOutboundGrantErrorCode::CandidateConsumed,
        );
    }

    #[test]
    fn revoked_confirmation_cannot_reissue_for_same_candidate() {
        let fixture = Fixture::new();
        let issued = issue_metadata(
            fixture
                .issue("event-revoked", destination())
                .expect("initial issue should succeed"),
        );
        fixture
            .grant_broker
            .revoke_ready_exact(&issued.grant_id)
            .expect("exact READY revoke should succeed");

        assert_error_code(
            fixture.issue("event-revoked", destination()),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );
        assert_error_code(
            fixture.issue("event-new-on-same-candidate", destination()),
            ScreenVisionOutboundGrantErrorCode::CandidateConsumed,
        );
        assert_error_code(
            fixture.grant_broker.claim_exact_for_delivery(
                &issued.grant_id,
                "delivery-revoked",
                &fixture.candidate_id,
                destination(),
            ),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );
        assert_error_code(
            fixture.grant_broker.get_exact(&issued.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );
    }

    #[test]
    fn same_candidate_ready_rejects_confirmation_ping_pong() {
        let fixture = Fixture::new();
        let issued = issue_metadata(
            fixture
                .issue("event-ping-a", destination())
                .expect("initial issue should succeed"),
        );

        assert_error_code(
            fixture.issue("event-ping-b", destination()),
            ScreenVisionOutboundGrantErrorCode::GrantInUse,
        );
        let replayed = issue_metadata(
            fixture
                .issue("event-ping-a", destination())
                .expect("original confirmation should replay"),
        );
        assert_eq!(replayed.grant_id, issued.grant_id);
    }

    #[test]
    fn new_candidate_can_progress_after_terminal_state_and_stale_ids_cannot_touch_it() {
        let fixture = Fixture::new();
        let old = issue_metadata(
            fixture
                .issue("event-candidate-a", destination())
                .expect("initial issue should succeed"),
        );
        fixture
            .grant_broker
            .revoke_ready_exact(&old.grant_id)
            .expect("candidate A should become consumed");

        let fence = fixture
            .session_gate
            .life_fence_for(LIFE_A)
            .expect("test session should be armed")
            .to_string();
        let new_candidate = fixture
            .candidate_broker
            .replace_candidate(LIFE_A, &fence, REVISION_A, projection())
            .expect("candidate B should install");
        let new_ready = issue_metadata(
            fixture
                .issue_with("event-candidate-b", &new_candidate, destination())
                .expect("new candidate should issue a new READY"),
        );
        assert_ne!(old.grant_id, new_ready.grant_id);
        assert_eq!(new_ready.candidate_id, new_candidate);

        assert_error_code(
            fixture.grant_broker.revoke_ready_exact(&old.grant_id),
            ScreenVisionOutboundGrantErrorCode::GrantMismatch,
        );
        assert_error_code(
            fixture
                .grant_broker
                .retire_bound_after_success(&old.grant_id, "delivery-a"),
            ScreenVisionOutboundGrantErrorCode::GrantMismatch,
        );
        assert_eq!(
            fixture
                .grant_broker
                .get_exact(&new_ready.grant_id)
                .expect("stale cleanup must preserve candidate B READY")
                .candidate_id,
            new_candidate
        );
    }

    #[test]
    fn consumed_same_confirmation_with_changed_destination_is_a_conflict() {
        let fixture = Fixture::new();
        let issued = issue_metadata(
            fixture
                .issue("event-consumed-conflict", destination())
                .expect("initial issue should succeed"),
        );
        fixture
            .grant_broker
            .revoke_ready_exact(&issued.grant_id)
            .expect("exact READY revoke should succeed");

        assert_error_code(
            fixture.issue(
                "event-consumed-conflict",
                destination_with("profile-b", BASE_URL_A, MODEL_NAME_A, PROFILE_UPDATED_AT_A),
            ),
            ScreenVisionOutboundGrantErrorCode::ConfirmationEventConflict,
        );
        assert_error_code(
            fixture.issue("event-consumed-conflict", destination()),
            ScreenVisionOutboundGrantErrorCode::GrantConsumed,
        );
    }

    #[test]
    fn grant_module_has_no_pixel_network_provider_or_ipc_surface() {
        let production = include_str!("screen_vision_outbound_grant.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source should precede tests");

        for forbidden in [
            "ScreenFrame",
            "as_bytes",
            "base64",
            "multipart",
            "reqwest",
            "Client",
            ".send(",
            "SecretStore",
            "ModelPurpose",
            "VisionProvider",
            "StorageService",
            "serde::Serialize",
            "tauri::command",
            "invoke",
            "cancel_any",
            "revoke_grant(",
            "fn clear(",
        ] {
            assert!(
                !production.contains(forbidden),
                "grant production source must not contain {forbidden}"
            );
        }
    }
}
