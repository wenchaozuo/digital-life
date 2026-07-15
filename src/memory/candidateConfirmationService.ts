import { invoke } from "@tauri-apps/api/core";
import type {
  PreparedCandidateConfirmation,
  CandidateConfirmationResult,
  CancelCandidateConfirmationResult,
} from "./candidateConfirmationTypes";
import {
  CandidateConfirmationError,
  toCandidateConfirmationError,
} from "./candidateConfirmationTypes";

// ── Input Validation ──────────────────────────────────────────────────

function validateCandidateId(candidateId: string): void {
  if (typeof candidateId !== "string" || candidateId.trim().length === 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INVALID_REQUEST",
      "candidateId must be a non-empty string",
      false,
    );
  }
}

function validateApprovalToken(approvalToken: string): void {
  if (typeof approvalToken !== "string" || approvalToken.trim().length === 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INVALID_REQUEST",
      "approvalToken must be a non-empty string",
      false,
    );
  }
}

// ── Response Validation ───────────────────────────────────────────────

function validatePrepareResponse(
  response: unknown,
  expectedCandidateId: string,
): PreparedCandidateConfirmation {
  if (!isRecord(response)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      "Invalid prepare response structure",
      false,
    );
  }

  if (response.candidateId !== expectedCandidateId) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      "Prepare response candidateId mismatch",
      false,
    );
  }

  return response as unknown as PreparedCandidateConfirmation;
}

function validateConfirmResponse(
  response: unknown,
  expectedCandidateId: string,
): CandidateConfirmationResult {
  if (!isRecord(response)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      "Invalid confirm response structure",
      false,
    );
  }

  if (response.candidateId !== expectedCandidateId) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      "Confirm response candidateId mismatch",
      false,
    );
  }

  return response as unknown as CandidateConfirmationResult;
}

function validateCancelResponse(
  response: unknown,
  expectedCandidateId: string,
): CancelCandidateConfirmationResult {
  if (!isRecord(response)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      "Invalid cancel response structure",
      false,
    );
  }

  if (response.candidateId !== expectedCandidateId) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      "Cancel response candidateId mismatch",
      false,
    );
  }

  return response as unknown as CancelCandidateConfirmationResult;
}

// ── Service Implementation ────────────────────────────────────────────

export class CandidateConfirmationService {
  /**
   * Prepare a candidate for confirmation and return a preview plus Approval Token.
   *
   * @param candidateId - The ID of the candidate to prepare
   * @returns The prepared confirmation with preview and token
   * @throws CandidateConfirmationError if the operation fails
   */
  async prepareCandidateConfirmation(
    candidateId: string,
  ): Promise<PreparedCandidateConfirmation> {
    validateCandidateId(candidateId);

    try {
      const response = await invoke<unknown>("prepare_candidate_confirmation", {
        request: { candidateId },
      });
      return validatePrepareResponse(response, candidateId);
    } catch (error: unknown) {
      throw toCandidateConfirmationError(error);
    }
  }

  /**
   * Confirm a candidate using its Approval Token, promoting it to a memory.
   *
   * @param candidateId - The ID of the candidate to confirm
   * @param approvalToken - The approval token from prepare
   * @returns The confirmation result
   * @throws CandidateConfirmationError if the operation fails
   */
  async confirmCandidateMemory(
    candidateId: string,
    approvalToken: string,
  ): Promise<CandidateConfirmationResult> {
    validateCandidateId(candidateId);
    validateApprovalToken(approvalToken);

    try {
      const response = await invoke<unknown>("confirm_candidate_memory", {
        request: { candidateId, approvalToken },
      });
      return validateConfirmResponse(response, candidateId);
    } catch (error: unknown) {
      throw toCandidateConfirmationError(error);
    }
  }

  /**
   * Cancel a prepared confirmation, retiring the Approval Token.
   *
   * @param candidateId - The ID of the candidate to cancel
   * @param approvalToken - The approval token from prepare
   * @returns The cancellation result
   * @throws CandidateConfirmationError if the operation fails
   */
  async cancelCandidateConfirmationApproval(
    candidateId: string,
    approvalToken: string,
  ): Promise<CancelCandidateConfirmationResult> {
    validateCandidateId(candidateId);
    validateApprovalToken(approvalToken);

    try {
      const response = await invoke<unknown>("cancel_candidate_confirmation_approval", {
        request: { candidateId, approvalToken },
      });
      return validateCancelResponse(response, candidateId);
    } catch (error: unknown) {
      throw toCandidateConfirmationError(error);
    }
  }
}

// ── Helper ────────────────────────────────────────────────────────────

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

// ── Singleton ─────────────────────────────────────────────────────────

export const candidateConfirmationService = new CandidateConfirmationService();
