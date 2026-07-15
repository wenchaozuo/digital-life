import { defineStore } from "pinia";
import { computed, ref } from "vue";
import type {
  CandidateConfirmationResult,
  PreparedCandidateConfirmation,
  PreparedCandidateConfirmationPreview,
} from "../memory/candidateConfirmationTypes.ts";
import {
  CandidateConfirmationError,
  toCandidateConfirmationError,
} from "../memory/candidateConfirmationTypes.ts";
import {
  candidateConfirmationService,
  type CandidateConfirmationClient,
} from "../memory/candidateConfirmationService.ts";

export type CandidateConfirmationPhase =
  | "idle"
  | "preparing"
  | "prepared"
  | "confirming"
  | "cancelling"
  | "succeeded"
  | "failed";

function localError(message: string): CandidateConfirmationError {
  return new CandidateConfirmationError(
    "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
    message,
    "none",
  );
}

function previewOf(
  prepared: PreparedCandidateConfirmation,
): PreparedCandidateConfirmationPreview {
  const { approvalToken: _approvalToken, ...preview } = prepared;
  return preview;
}

export function createCandidateConfirmationStore(
  service: CandidateConfirmationClient = candidateConfirmationService,
) {
  return defineStore("candidateConfirmation", () => {
    let generation = 0;
    let privateApprovalToken: string | null = null;

    const candidateId = ref<string | null>(null);
    const prepared = ref<PreparedCandidateConfirmationPreview | null>(null);
    const phase = ref<CandidateConfirmationPhase>("idle");
    const error = ref<CandidateConfirmationError | null>(null);
    const result = ref<CandidateConfirmationResult | null>(null);

    const isIdle = computed(() => phase.value === "idle");
    const isPreparing = computed(() => phase.value === "preparing");
    const isPrepared = computed(() => phase.value === "prepared");
    const isConfirming = computed(() => phase.value === "confirming");
    const isCancelling = computed(() => phase.value === "cancelling");
    const isSucceeded = computed(() => phase.value === "succeeded");
    const isFailed = computed(() => phase.value === "failed");

    const isPreparedConfirmationExpired = computed(() => {
      if (!prepared.value?.expiresAt) return false;
      const timestamp = Date.parse(prepared.value.expiresAt);
      return !Number.isFinite(timestamp) || Date.now() > timestamp;
    });

    const canPrepare = computed(() =>
      phase.value === "idle" ||
      phase.value === "prepared" ||
      phase.value === "failed" ||
      phase.value === "succeeded",
    );
    const canConfirm = computed(() =>
      phase.value === "prepared" &&
      prepared.value !== null &&
      privateApprovalToken !== null &&
      !isPreparedConfirmationExpired.value,
    );
    const canCancel = computed(() =>
      phase.value === "prepared" &&
      prepared.value !== null &&
      privateApprovalToken !== null,
    );

    function nextGeneration(): number {
      generation += 1;
      return generation;
    }

    function isCurrentGeneration(operationGeneration: number): boolean {
      return generation === operationGeneration;
    }

    function clearState(): void {
      privateApprovalToken = null;
      candidateId.value = null;
      prepared.value = null;
      phase.value = "idle";
      error.value = null;
      result.value = null;
    }

    function clearPreparedAuthorization(): void {
      privateApprovalToken = null;
      prepared.value = null;
    }

    function rejectInvalidTransition(): never {
      throw localError("The confirmation action is not available in the current state.");
    }

    function assertPreparedCandidate(expectedCandidateId: string): string {
      if (
        phase.value !== "prepared" ||
        !prepared.value ||
        !privateApprovalToken ||
        prepared.value.candidateId !== expectedCandidateId
      ) {
        throw localError("The prepared candidate does not match this action.");
      }
      return privateApprovalToken;
    }

    async function prepare(id: string): Promise<void> {
      if (!canPrepare.value) rejectInvalidTransition();

      const operationGeneration = nextGeneration();
      clearState();
      candidateId.value = id;
      phase.value = "preparing";

      try {
        const response = await service.prepareCandidateConfirmation(id);
        if (!isCurrentGeneration(operationGeneration)) return;

        privateApprovalToken = response.approvalToken;
        prepared.value = previewOf(response);
        phase.value = "prepared";
      } catch (caught: unknown) {
        if (!isCurrentGeneration(operationGeneration)) return;

        clearPreparedAuthorization();
        candidateId.value = null;
        error.value = toCandidateConfirmationError(caught);
        phase.value = "failed";
      }
    }

    async function confirm(expectedCandidateId: string): Promise<void> {
      const approvalToken = assertPreparedCandidate(expectedCandidateId);
      if (isPreparedConfirmationExpired.value) {
        clearPreparedAuthorization();
        phase.value = "failed";
        error.value = localError("The approval token has expired locally.");
        return;
      }

      const operationGeneration = nextGeneration();
      phase.value = "confirming";
      error.value = null;

      try {
        const response = await service.confirmCandidateMemory(expectedCandidateId, approvalToken);
        if (!isCurrentGeneration(operationGeneration)) return;

        result.value = response;
        clearPreparedAuthorization();
        phase.value = "succeeded";
      } catch (caught: unknown) {
        if (!isCurrentGeneration(operationGeneration)) return;

        const confirmationError = toCandidateConfirmationError(caught);
        error.value = confirmationError;

        if (confirmationError.action === "retrySameToken") {
          phase.value = "prepared";
          return;
        }

        clearPreparedAuthorization();
        phase.value = "failed";
      }
    }

    async function cancel(expectedCandidateId: string): Promise<void> {
      const approvalToken = assertPreparedCandidate(expectedCandidateId);
      const operationGeneration = nextGeneration();
      phase.value = "cancelling";
      error.value = null;

      try {
        const response = await service.cancelCandidateConfirmationApproval(
          expectedCandidateId,
          approvalToken,
        );
        if (!isCurrentGeneration(operationGeneration)) return;

        clearPreparedAuthorization();
        candidateId.value = null;

        if (!response.cancelled) {
          phase.value = "failed";
          error.value = localError(
            "Backend cancellation was not confirmed; local authorization cleared.",
          );
          return;
        }

        phase.value = "idle";
        error.value = null;
      } catch (_caught: unknown) {
        if (!isCurrentGeneration(operationGeneration)) return;

        clearPreparedAuthorization();
        candidateId.value = null;
        phase.value = "failed";
        error.value = localError(
          "Cancellation status unknown; local authorization cleared.",
        );
      }
    }

    function clearCandidateConfirmation(): void {
      nextGeneration();
      clearState();
    }

    return {
      candidateId,
      prepared,
      phase,
      error,
      result,
      isIdle,
      isPreparing,
      isPrepared,
      isConfirming,
      isCancelling,
      isSucceeded,
      isFailed,
      isPreparedConfirmationExpired,
      canPrepare,
      canConfirm,
      canCancel,
      prepare,
      confirm,
      cancel,
      clearCandidateConfirmation,
    };
  });
}

export const useCandidateConfirmationStore = createCandidateConfirmationStore();
