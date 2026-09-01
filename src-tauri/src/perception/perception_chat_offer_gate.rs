//! Process-local single-slot gate for Chat perception offers.
//!
//! D24 OCR and D27 Cloud Vision use different payload authorities, but they
//! share one Chat-facing attachment slot.  This gate is deliberately only a
//! coordination marker: the source brokers remain responsible for validating
//! and retiring their own authority.

use std::sync::Mutex;

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_ATTACHMENT_ID_CHARACTERS: usize = 128;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PerceptionChatSourceKind {
    LocalOcr,
    CloudVision,
}

impl PerceptionChatSourceKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOcr => "localOcr",
            Self::CloudVision => "cloudVision",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PerceptionChatOfferGateErrorCode {
    AttachmentInUse,
    CrossSourceInUse,
    SynchronizationUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PerceptionChatOfferGateError {
    pub(crate) code: PerceptionChatOfferGateErrorCode,
}

impl PerceptionChatOfferGateError {
    const fn in_use() -> Self {
        Self {
            code: PerceptionChatOfferGateErrorCode::AttachmentInUse,
        }
    }

    const fn synchronization_unavailable() -> Self {
        Self {
            code: PerceptionChatOfferGateErrorCode::SynchronizationUnavailable,
        }
    }

    const fn cross_source_in_use() -> Self {
        Self {
            code: PerceptionChatOfferGateErrorCode::CrossSourceInUse,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PerceptionChatOfferReservation {
    source: PerceptionChatSourceKind,
    previous_offered_attachment_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum GateState {
    Empty,
    Offering {
        source: PerceptionChatSourceKind,
        previous_offered_attachment_id: Option<String>,
    },
    Offered {
        source: PerceptionChatSourceKind,
        attachment_id: String,
    },
    Bound {
        source: PerceptionChatSourceKind,
        attachment_id: String,
    },
}

/// One process-local cross-source Chat perception offer gate.
///
/// It intentionally has no queue, history, payload, persistence, or Life
/// map.  Same-source replacement is permitted only while the previous
/// attachment is still OFFERED; a BOUND attachment blocks every new offer.
pub(crate) struct PerceptionChatOfferGate {
    state: Mutex<GateState>,
    #[cfg(test)]
    fail_next_bound_clear: AtomicBool,
}

impl PerceptionChatOfferGate {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(GateState::Empty),
            #[cfg(test)]
            fail_next_bound_clear: AtomicBool::new(false),
        }
    }

    /// Reserves the single offer slot.  An unbound same-source offer may be
    /// replaced; a cross-source offer or any BOUND offer fails fast.
    pub(crate) fn begin_offer(
        &self,
        source: PerceptionChatSourceKind,
    ) -> Result<PerceptionChatOfferReservation, PerceptionChatOfferGateError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PerceptionChatOfferGateError::synchronization_unavailable())?;
        let previous = match &*state {
            GateState::Empty => None,
            GateState::Offered {
                source: current_source,
                attachment_id,
            } if *current_source == source => Some(attachment_id.clone()),
            GateState::Offered {
                source: current_source,
                ..
            } if *current_source != source => {
                return Err(PerceptionChatOfferGateError::cross_source_in_use())
            }
            GateState::Bound {
                source: current_source,
                ..
            } if *current_source != source => {
                return Err(PerceptionChatOfferGateError::cross_source_in_use())
            }
            GateState::Offered { .. } | GateState::Bound { .. } | GateState::Offering { .. } => {
                return Err(PerceptionChatOfferGateError::in_use())
            }
        };
        *state = GateState::Offering {
            source,
            previous_offered_attachment_id: previous.clone(),
        };
        Ok(PerceptionChatOfferReservation {
            source,
            previous_offered_attachment_id: previous,
        })
    }

    pub(crate) fn commit_offer(
        &self,
        reservation: &PerceptionChatOfferReservation,
        attachment_id: String,
    ) -> Result<(), PerceptionChatOfferGateError> {
        validate_attachment_id(&attachment_id)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PerceptionChatOfferGateError::synchronization_unavailable())?;
        match &*state {
            GateState::Offering { source, .. } if *source == reservation.source => {
                *state = GateState::Offered {
                    source: reservation.source,
                    attachment_id,
                };
                Ok(())
            }
            _ => Err(PerceptionChatOfferGateError::in_use()),
        }
    }

    /// Restores the previous same-source OFFERED marker when an offer fails
    /// before its source broker can replace it.  This is authority-shrinking
    /// coordination only; it never recreates source payload.
    pub(crate) fn abort_offer(
        &self,
        reservation: &PerceptionChatOfferReservation,
    ) -> Result<(), PerceptionChatOfferGateError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| PerceptionChatOfferGateError::synchronization_unavailable())?;
        match &*state {
            GateState::Offering { source, .. } if *source == reservation.source => {
                *state = match &reservation.previous_offered_attachment_id {
                    Some(attachment_id) => GateState::Offered {
                        source: reservation.source,
                        attachment_id: attachment_id.clone(),
                    },
                    None => GateState::Empty,
                };
                Ok(())
            }
            _ => Err(PerceptionChatOfferGateError::in_use()),
        }
    }

    pub(crate) fn mark_bound(
        &self,
        source: PerceptionChatSourceKind,
        attachment_id: &str,
    ) -> Result<(), PerceptionChatOfferGateError> {
        validate_attachment_id(attachment_id)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PerceptionChatOfferGateError::synchronization_unavailable())?;
        match &*state {
            GateState::Offered {
                source: current_source,
                attachment_id: current_attachment_id,
            } if *current_source == source && current_attachment_id == attachment_id => {
                *state = GateState::Bound {
                    source,
                    attachment_id: attachment_id.to_string(),
                };
                Ok(())
            }
            GateState::Bound {
                source: current_source,
                attachment_id: current_attachment_id,
            } if *current_source == source && current_attachment_id == attachment_id => Ok(()),
            _ => Err(PerceptionChatOfferGateError::in_use()),
        }
    }

    /// Removes only an OFFERED exact locator.  A BOUND marker is deliberately
    /// retained until the source broker performs exact successful retirement.
    pub(crate) fn clear_offered_exact(
        &self,
        source: PerceptionChatSourceKind,
        attachment_id: &str,
    ) -> Result<bool, PerceptionChatOfferGateError> {
        validate_attachment_id(attachment_id)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| PerceptionChatOfferGateError::synchronization_unavailable())?;
        if matches!(
            &*state,
            GateState::Offered {
                source: current_source,
                attachment_id: current_attachment_id,
            } if *current_source == source && current_attachment_id == attachment_id
        ) {
            *state = GateState::Empty;
            return Ok(true);
        }
        Ok(false)
    }

    /// Removes only a BOUND exact locator after the source authority has
    /// retired successfully.  It also accepts an already-cleared OFFERED
    /// state so exact cleanup remains idempotent.
    pub(crate) fn clear_bound_exact(
        &self,
        source: PerceptionChatSourceKind,
        attachment_id: &str,
    ) -> Result<bool, PerceptionChatOfferGateError> {
        validate_attachment_id(attachment_id)?;
        #[cfg(test)]
        if self.fail_next_bound_clear.swap(false, Ordering::AcqRel) {
            return Err(PerceptionChatOfferGateError::synchronization_unavailable());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| PerceptionChatOfferGateError::synchronization_unavailable())?;
        if matches!(
            &*state,
            GateState::Bound {
                source: current_source,
                attachment_id: current_attachment_id,
            } if *current_source == source && current_attachment_id == attachment_id
        ) {
            *state = GateState::Empty;
            return Ok(true);
        }
        Ok(false)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_bound_clear_for_test(&self) {
        self.fail_next_bound_clear.store(true, Ordering::Release);
    }

    pub(crate) fn is_bound_exact(
        &self,
        source: PerceptionChatSourceKind,
        attachment_id: &str,
    ) -> Result<bool, PerceptionChatOfferGateError> {
        validate_attachment_id(attachment_id)?;
        let state = self
            .state
            .lock()
            .map_err(|_| PerceptionChatOfferGateError::synchronization_unavailable())?;
        Ok(matches!(
            &*state,
            GateState::Bound {
                source: current_source,
                attachment_id: current_attachment_id,
            } if *current_source == source && current_attachment_id == attachment_id
        ))
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Option<(PerceptionChatSourceKind, String, bool)> {
        let state = self.state.lock().ok()?;
        match &*state {
            GateState::Empty | GateState::Offering { .. } => None,
            GateState::Offered {
                source,
                attachment_id,
            } => Some((*source, attachment_id.clone(), false)),
            GateState::Bound {
                source,
                attachment_id,
            } => Some((*source, attachment_id.clone(), true)),
        }
    }
}

fn validate_attachment_id(value: &str) -> Result<(), PerceptionChatOfferGateError> {
    if value.trim().is_empty() || value.chars().count() > MAX_ATTACHMENT_ID_CHARACTERS {
        return Err(PerceptionChatOfferGateError {
            code: PerceptionChatOfferGateErrorCode::SynchronizationUnavailable,
        });
    }
    Ok(())
}
