//! Process-local concurrency authority for D23-C1 screen operations.
//!
//! The picker and one-shot capture share this single fail-fast gate.  It is
//! deliberately not persisted and has no queue: a fresh process starts idle,
//! and a second operation receives a bounded busy result while the first
//! operation owns the permit.

use std::sync::atomic::{AtomicBool, Ordering};

/// Canonical application-managed screen-operation coordinator.
///
/// `false` represents `IDLE` and `true` represents `BUSY`.  The compare-and-
/// exchange makes acquisition fail immediately rather than waiting behind a
/// native picker or frame operation.
pub(crate) struct ScreenCaptureOperationGate {
    busy: AtomicBool,
}

impl ScreenCaptureOperationGate {
    pub(crate) fn new() -> Self {
        Self {
            busy: AtomicBool::new(false),
        }
    }

    /// Attempts to enter the single in-flight screen-operation slot.
    ///
    /// The returned permit releases the gate on every normal exit path.  Its
    /// `Drop` implementation also releases it during ordinary Rust panic
    /// unwinding.
    pub(crate) fn try_enter(&self) -> Result<ScreenCaptureOperationPermit<'_>, ()> {
        self.busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| ScreenCaptureOperationPermit { gate: self })
            .map_err(|_| ())
    }
}

/// RAII ownership of the single screen-operation slot.
pub(crate) struct ScreenCaptureOperationPermit<'a> {
    gate: &'a ScreenCaptureOperationGate,
}

impl Drop for ScreenCaptureOperationPermit<'_> {
    fn drop(&mut self) {
        self.gate.busy.store(false, Ordering::Release);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_gate_is_idle_and_releases_after_permit_drop() {
        let gate = ScreenCaptureOperationGate::new();

        let permit = gate.try_enter().expect("fresh gate must be idle");
        assert!(gate.try_enter().is_err(), "held gate must report busy");
        drop(permit);
        assert!(gate.try_enter().is_ok(), "dropped permit must release gate");
    }

    #[test]
    fn failed_try_enter_is_fail_fast_and_does_not_queue() {
        let gate = ScreenCaptureOperationGate::new();
        let _permit = gate.try_enter().expect("first operation must enter");

        assert!(gate.try_enter().is_err());
        assert!(gate.try_enter().is_err());
    }

    #[test]
    fn permit_releases_during_panic_unwind() {
        let gate = ScreenCaptureOperationGate::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _permit = gate.try_enter().expect("operation must enter");
            panic!("test panic after acquiring operation permit");
        }));

        assert!(result.is_err());
        assert!(gate.try_enter().is_ok());
    }
}
