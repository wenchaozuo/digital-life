//! Canonical process-local screen-capture target broker for D23-C1.
//!
//! The broker represents at most the currently selected process-local capture
//! target.  It never persists a `GraphicsCaptureItem`, HWND, PID, title,
//! process path, or monitor identifier to SQLite, never uses
//! localStorage/sessionStorage/frontend state or environment variables as
//! authority, and resets to `NONE` on application restart.
//!
//! The three authorities remain independent:
//!
//! ```text
//! persistent consent ≠ session arm ≠ capture target
//! ```
//!
//! A target is bound to the session-generation fence that selected it, so a
//! target selected under Life A can never silently become authority for Life
//! B after the gate is rearmed.

use std::sync::Mutex;

use serde::Serialize;

/// A de-identified, user-facing target descriptor.  It carries only a stable
/// per-process index and a bounded display label; no HWND, PID, title,
/// process path, or monitor device path ever leaves the backend.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ScreenCaptureTargetDescriptor {
    pub(crate) index: u64,
    pub(crate) kind: String,
    pub(crate) label: String,
}

/// The opaque process-local capture target.  The native handle lives only in
/// the backend process and is never serialized.  `native` is `Option` only so
/// fence-logic unit tests can run without a live Windows capture item;
/// production selection always installs `Some`.
#[derive(Clone, Debug)]
pub(crate) struct ScreenCaptureTarget {
    /// The session-generation fence that selected this target.
    pub(crate) life_fence: u64,
    /// De-identified descriptor for status display.
    pub(crate) descriptor: ScreenCaptureTargetDescriptor,
    /// Opaque native capture item.  Windows: `GraphicsCaptureItem`.
    #[cfg(windows)]
    pub(crate) native: Option<windows::Graphics::Capture::GraphicsCaptureItem>,
    #[cfg(not(windows))]
    pub(crate) native: Option<()>,
}

#[derive(Debug)]
enum BrokerState {
    None,
    Selected(ScreenCaptureTarget),
}

pub(crate) struct ScreenCaptureTargetBroker {
    state: Mutex<BrokerState>,
}

impl ScreenCaptureTargetBroker {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(BrokerState::None),
        }
    }

    /// Replaces the current target only after a valid selection.  The old
    /// target is retired (dropped) in the same lock.  Cancellation never
    /// fabricates a target and never clears an existing valid one unless the
    /// caller explicitly asks to clear.
    pub(crate) fn select(
        &self,
        life_fence: u64,
        descriptor: ScreenCaptureTargetDescriptor,
        native: impl Into<NativeCaptureItem>,
    ) {
        let mut state = self.state.lock().unwrap();
        *state = BrokerState::Selected(ScreenCaptureTarget {
            life_fence,
            descriptor,
            native: Some(native.into()),
        });
    }

    /// Clears the current target (used on session disarm/rebind as an
    /// additional proactive defense; correctness never depends on it).
    pub(crate) fn clear(&self) {
        let mut state = self.state.lock().unwrap();
        *state = BrokerState::None;
    }

    /// The current target if it exists AND its life fence matches the given
    /// fence.  A target bound to a different (stale) fence is treated as
    /// absent, so Life B can never inherit Life A's target.
    pub(crate) fn current_target_for_fence(&self, life_fence: u64) -> Option<ScreenCaptureTarget> {
        match &*self.state.lock().unwrap() {
            BrokerState::None => None,
            BrokerState::Selected(target) if target.life_fence == life_fence => {
                Some(target.clone())
            }
            BrokerState::Selected(_) => None,
        }
    }

    /// Convenience for the capture path: resolves the gate's current life
    /// fence and returns the matching target.  The fence is the opaque
    /// generation token of the armed session; a rearmed session yields a new
    /// fence, so the old target is automatically rejected.
    pub(crate) fn current_target_for_life(
        &self,
        gate: &crate::perception::screen_policy::ScreenPerceptionSessionGate,
        life_id: &str,
    ) -> Option<ScreenCaptureTarget> {
        let fence = gate.life_fence_for(life_id)?;
        self.current_target_for_fence(fence)
    }

    /// De-identified status for Settings display.
    pub(crate) fn current_descriptor(&self) -> Option<ScreenCaptureTargetDescriptor> {
        match &*self.state.lock().unwrap() {
            BrokerState::None => None,
            BrokerState::Selected(target) => Some(target.descriptor.clone()),
        }
    }

    /// Test-only installation path that stores no native item, so dropping
    /// the broker is always safe.  Unit tests exercise the fence logic only;
    /// the native provider is never invoked with such a target.
    #[cfg(test)]
    pub(crate) fn install_target_for_test(
        &self,
        life_fence: u64,
        descriptor: ScreenCaptureTargetDescriptor,
    ) {
        let mut state = self.state.lock().unwrap();
        *state = BrokerState::Selected(ScreenCaptureTarget {
            life_fence,
            descriptor,
            native: None,
        });
    }
}

/// Type alias for the opaque native capture item, platform-split.
#[cfg(windows)]
pub(crate) type NativeCaptureItem = windows::Graphics::Capture::GraphicsCaptureItem;

#[cfg(not(windows))]
pub(crate) type NativeCaptureItem = ();

#[cfg(test)]
mod tests {
    use super::*;
    use crate::perception::screen_policy::ScreenPerceptionSessionGate;

    fn descriptor(index: u64, label: &str) -> ScreenCaptureTargetDescriptor {
        ScreenCaptureTargetDescriptor {
            index,
            kind: "test".to_string(),
            label: label.to_string(),
        }
    }

    #[test]
    fn fresh_broker_has_no_target() {
        let broker = ScreenCaptureTargetBroker::new();
        assert_eq!(broker.current_descriptor(), None);
        assert!(broker.current_target_for_fence(1).is_none());
    }

    #[test]
    fn select_replaces_previous_target_and_clear_removes_it() {
        let broker = ScreenCaptureTargetBroker::new();
        broker.install_target_for_test(1, descriptor(0, "A"));
        assert_eq!(broker.current_descriptor().unwrap().label, "A");
        broker.install_target_for_test(2, descriptor(1, "B"));
        assert_eq!(broker.current_descriptor().unwrap().label, "B");
        broker.clear();
        assert_eq!(broker.current_descriptor(), None);
    }

    #[test]
    fn stale_fence_target_is_rejected_for_new_life() {
        let broker = ScreenCaptureTargetBroker::new();
        let gate = ScreenPerceptionSessionGate::new();

        // Life A arms (fence 1) and selects a target under that fence.
        gate.arm_for_life("life-a");
        let fence_a = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(fence_a, descriptor(0, "A"));
        assert!(broker.current_target_for_life(&gate, "life-a").is_some());

        // Life B rearms (fence 2); A's target must not be inherited.
        gate.arm_for_life("life-b");
        assert!(broker.current_target_for_life(&gate, "life-b").is_none());
        assert!(broker.current_target_for_life(&gate, "life-a").is_none());
    }

    #[test]
    fn disarm_invalidates_target_through_fence() {
        let broker = ScreenCaptureTargetBroker::new();
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let fence = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(fence, descriptor(0, "A"));

        gate.disarm();
        assert!(broker.current_target_for_life(&gate, "life-a").is_none());
    }

    #[test]
    fn rearm_same_life_gets_new_fence_and_rejects_old_target() {
        let broker = ScreenCaptureTargetBroker::new();
        let gate = ScreenPerceptionSessionGate::new();
        gate.arm_for_life("life-a");
        let fence_first = gate.life_fence_for("life-a").unwrap();
        broker.install_target_for_test(fence_first, descriptor(0, "A"));

        gate.disarm();
        gate.arm_for_life("life-a");
        let fence_second = gate.life_fence_for("life-a").unwrap();
        assert_ne!(fence_first, fence_second);
        assert!(broker.current_target_for_life(&gate, "life-a").is_none());
    }
}
