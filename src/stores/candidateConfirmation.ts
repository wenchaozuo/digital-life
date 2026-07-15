import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type {
  PreparedCandidateConfirmation,
  CandidateConfirmationResult,
} from "../memory/candidateConfirmationTypes";
import {
  CandidateConfirmationError,
  isReprepareRequired,
  isRetryable,
} from "../memory/candidateConfirmationTypes";
import { candidateConfirmationService } from "../memory/candidateConfirmationService";

// ── Types ─────────────────────────────────────────────────────────────

export type CandidateConfirmationPhase =
  | "idle"
  | "preparing"
  | "prepared"
  | "confirming"
  | "cancelling"
  | "succeeded"
  | "failed";

// ── Store ─────────────────────────────────────────────────────────────

export const useCandidateConfirmationStore = defineStore(
  "candidateConfirmation",
  () => {
    // ── State ───────────────────────────────────────────────────────

    const candidateId = ref<string | null>(null);
    const prepared = ref<PreparedCandidateConfirmation | null>(null);
    const phase = ref<CandidateConfirmationPhase>("idle");
    const error = ref<CandidateConfirmationError | null>(null);
    const result = ref<CandidateConfirmationResult | null>(null);

    // Private: token is only stored in prepared.value.approvalToken
    // No separate copy to avoid desync

    // ── Getters ─────────────────────────────────────────────────────

    const isIdle = computed(() => phase.value === "idle");
    const isPreparing = computed(() => phase.value === "preparing");
    const isPrepared = computed(() => phase.value === "prepared");
    const isConfirming = computed(() => phase.value === "confirming");
    const isCancelling = computed(() => phase.value === "cancelling");
    const isSucceeded = computed(() => phase.value === "succeeded");
    const isFailed = computed(() => phase.value === "failed");

    const approvalToken = computed(() => prepared.value?.approvalToken ?? null);

    const isPreparedConfirmationExpired = computed(() => {
      if (!prepared.value?.expiresAt) {
        return false;
      }
      try {
        const expiresAt = new Date(prepared.value.expiresAt).getTime();
        return Date.now() > expiresAt;
      } catch {
        return true;
      }
    });

    const canPrepare = computed(() =>
      phase.value === "idle" || phase.value === "failed" || phase.value === "succeeded",
    );

    const canConfirm = computed(() =>
      phase.value === "prepared" &&
      prepared.value !== null &&
      approvalToken.value !== null &&
      !isPreparedConfirmationExpired.value,
    );

    const canCancel = computed(() =>
      (phase.value === "prepared" || phase.value === "failed") &&
      prepared.value !== null &&
      approvalToken.value !== null,
    );

    // ── Actions ─────────────────────────────────────────────────────

    /**
     * Prepare a candidate for confirmation.
     * Guards against concurrent prepares and cleans up old state.
     */
    async function prepare(id: string): Promise<void> {
      // Guard: prevent concurrent prepares
      if (phase.value === "preparing" || phase.value === "confirming" || phase.value === "cancelling") {
        return;
      }

      // Clean up old state
      clearState();

      candidateId.value = id;
      phase.value = "preparing";
      error.value = null;

      try {
        const response = await candidateConfirmationService.prepareCandidateConfirmation(id);

        // Verify response candidateId matches request
        if (response.candidateId !== id) {
          throw new CandidateConfirmationError(
            "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
            "Prepare response candidateId mismatch",
            false,
          );
        }

        prepared.value = response;
        phase.value = "prepared";
      } catch (err: unknown) {
        const confirmationError = err instanceof CandidateConfirmationError
          ? err
          : new CandidateConfirmationError(
              "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
              "Prepare failed unexpectedly",
              false,
            );
        error.value = confirmationError;
        phase.value = "failed";
        // Clear any partial state
        prepared.value = null;
        candidateId.value = null;
      }
    }

    /**
     * Confirm the prepared candidate using the approval token.
     * Only callable from "prepared" phase.
     */
    async function confirm(): Promise<void> {
      // Guard: can only confirm from prepared state
      if (phase.value !== "prepared") {
        return;
      }

      // Guard: prevent concurrent confirms
      if (!prepared.value || !approvalToken.value) {
        return;
      }

      const currentCandidateId = prepared.value.candidateId;
      const currentToken = approvalToken.value;

      phase.value = "confirming";
      error.value = null;

      try {
        const response = await candidateConfirmationService.confirmCandidateMemory(
          currentCandidateId,
          currentToken,
        );

        // Verify response candidateId
        if (response.candidateId !== currentCandidateId) {
          throw new CandidateConfirmationError(
            "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
            "Confirm response candidateId mismatch",
            false,
          );
        }

        // Success: clear token immediately, save minimal result
        result.value = {
          candidateId: response.candidateId,
          confirmedMemoryId: response.confirmedMemoryId,
          outcome: response.outcome,
        };
        prepared.value = null; // Clears token
        phase.value = "succeeded";
      } catch (err: unknown) {
        const confirmationError = err instanceof CandidateConfirmationError
          ? err
          : new CandidateConfirmationError(
              "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
              "Confirm failed unexpectedly",
              false,
            );

        error.value = confirmationError;

        // Handle error based on type
        if (isReprepareRequired(confirmationError)) {
          // Token is invalid/expired/consumed/cancelled/context changed
          // Clear token and require re-prepare
          prepared.value = null;
          phase.value = "failed";
        } else if (isRetryable(confirmationError)) {
          // Token is still valid (storage unavailable, in-flight)
          // Keep prepared state so user can retry with same token
          phase.value = "prepared";
        } else {
          // Unknown or internal error: safest to clear
          prepared.value = null;
          phase.value = "failed";
        }
      }
    }

    /**
     * Cancel the prepared confirmation.
     * Cleans up token even if backend call fails.
     */
    async function cancel(): Promise<void> {
      // Guard: need prepared state with token
      if (!prepared.value || !approvalToken.value) {
        // If we have stale state, clean it up locally
        clearState();
        return;
      }

      const currentCandidateId = prepared.value.candidateId;
      const currentToken = approvalToken.value;

      phase.value = "cancelling";
      error.value = null;

      try {
        await candidateConfirmationService.cancelCandidateConfirmationApproval(
          currentCandidateId,
          currentToken,
        );
      } catch {
        // Even if cancel fails, clean up locally
        // We don't claim backend cancellation succeeded
      }

      // Always clean up local state
      prepared.value = null;
      candidateId.value = null;
      phase.value = "idle";
    }

    /**
     * Clear all confirmation state without making any backend calls.
     */
    function clearCandidateConfirmation(): void {
      clearState();
    }

    // ── Private Helpers ─────────────────────────────────────────────

    function clearState(): void {
      candidateId.value = null;
      prepared.value = null;
      phase.value = "idle";
      error.value = null;
      result.value = null;
    }

    // ── Return ──────────────────────────────────────────────────────

    return {
      // State
      candidateId,
      prepared,
      phase,
      error,
      result,

      // Getters
      isIdle,
      isPreparing,
      isPrepared,
      isConfirming,
      isCancelling,
      isSucceeded,
      isFailed,
      approvalToken,
      isPreparedConfirmationExpired,
      canPrepare,
      canConfirm,
      canCancel,

      // Actions
      prepare,
      confirm,
      cancel,
      clearCandidateConfirmation,
    };
  },
);
