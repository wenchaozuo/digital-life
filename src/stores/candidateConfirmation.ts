import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type {
  PreparedCandidateConfirmation,
  CandidateConfirmationResult,
} from "../memory/candidateConfirmationTypes.ts";
import {
  CandidateConfirmationError,
} from "../memory/candidateConfirmationTypes.ts";
import { candidateConfirmationService } from "../memory/candidateConfirmationService.ts";

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
    // ── Stale Promise Protection ─────────────────────────────────────

    let generation = 0;

    function nextGeneration(): number {
      generation += 1;
      return generation;
    }

    function isCurrentGeneration(value: number): boolean {
      return value === generation;
    }

    // ── State ───────────────────────────────────────────────────────

    const candidateId = ref<string | null>(null);
    const prepared = ref<PreparedCandidateConfirmation | null>(null);
    const phase = ref<CandidateConfirmationPhase>("idle");
    const error = ref<CandidateConfirmationError | null>(null);
    const result = ref<CandidateConfirmationResult | null>(null);

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
      const timestamp = Date.parse(prepared.value.expiresAt);
      if (!Number.isFinite(timestamp)) {
        return true; // Invalid date treated as expired
      }
      return Date.now() > timestamp;
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
     */
    async function prepare(id: string): Promise<void> {
      // Guard: prevent concurrent prepares
      if (phase.value === "preparing" || phase.value === "confirming" || phase.value === "cancelling") {
        return;
      }

      // Clean up old state and capture generation
      clearState();
      const myGeneration = nextGeneration();

      candidateId.value = id;
      phase.value = "preparing";
      error.value = null;

      try {
        const response = await candidateConfirmationService.prepareCandidateConfirmation(id);

        // Check generation before writing back
        if (!isCurrentGeneration(myGeneration)) return;

        prepared.value = response;
        phase.value = "prepared";
      } catch (err: unknown) {
        if (!isCurrentGeneration(myGeneration)) return;

        const confirmationError = err instanceof CandidateConfirmationError
          ? err
          : new CandidateConfirmationError(
              "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
              "The confirmation operation failed.",
              "none",
            );
        error.value = confirmationError;
        phase.value = "failed";
        prepared.value = null;
        candidateId.value = null;
      }
    }

    /**
     * Confirm the prepared candidate using the approval token.
     */
    async function confirm(): Promise<void> {
      // Guard: can only confirm from prepared state
      if (phase.value !== "prepared" || !prepared.value || !approvalToken.value) {
        return;
      }

      const currentCandidateId = prepared.value.candidateId;
      const currentToken = approvalToken.value;
      const myGeneration = nextGeneration();

      phase.value = "confirming";
      error.value = null;

      try {
        const response = await candidateConfirmationService.confirmCandidateMemory(
          currentCandidateId,
          currentToken,
        );

        if (!isCurrentGeneration(myGeneration)) return;

        // Success: clear token immediately, save minimal result
        result.value = {
          candidateId: response.candidateId,
          confirmedMemoryId: response.confirmedMemoryId,
          outcome: response.outcome,
        };
        prepared.value = null;
        phase.value = "succeeded";
      } catch (err: unknown) {
        if (!isCurrentGeneration(myGeneration)) return;

        const confirmationError = err instanceof CandidateConfirmationError
          ? err
          : new CandidateConfirmationError(
              "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
              "The confirmation operation failed.",
              "none",
            );

        error.value = confirmationError;

        // Handle error based on action
        switch (confirmationError.action) {
          case "reprepare":
            // Token is invalid/expired/consumed/cancelled/context changed
            prepared.value = null;
            phase.value = "failed";
            break;
          case "retrySameToken":
            // Token is still valid (storage unavailable, in-flight)
            phase.value = "prepared";
            break;
          case "retryPrepareLater":
          case "none":
          default:
            // Clear token for safety
            prepared.value = null;
            phase.value = "failed";
            break;
        }
      }
    }

    /**
     * Cancel the prepared confirmation.
     */
    async function cancel(): Promise<void> {
      if (!prepared.value || !approvalToken.value) {
        clearState();
        return;
      }

      const currentCandidateId = prepared.value.candidateId;
      const currentToken = approvalToken.value;
      const myGeneration = nextGeneration();

      phase.value = "cancelling";
      error.value = null;

      try {
        await candidateConfirmationService.cancelCandidateConfirmationApproval(
          currentCandidateId,
          currentToken,
        );

        if (!isCurrentGeneration(myGeneration)) return;

        // Cancel succeeded
        prepared.value = null;
        candidateId.value = null;
        phase.value = "idle";
        error.value = null;
      } catch (err: unknown) {
        if (!isCurrentGeneration(myGeneration)) return;

        // Cancel failed: clear token locally but report error
        prepared.value = null;
        candidateId.value = null;
        phase.value = "failed";
        error.value = new CandidateConfirmationError(
          "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
          "Cancellation status unknown; local authorization cleared.",
          "none",
        );
      }
    }

    /**
     * Clear all confirmation state without making any backend calls.
     */
    function clearCandidateConfirmation(): void {
      nextGeneration(); // Invalidate all in-flight promises
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
