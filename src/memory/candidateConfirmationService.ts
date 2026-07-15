import { invoke } from "@tauri-apps/api/core";
import type {
  PreparedCandidateConfirmation,
  CandidateConfirmationResult,
  CancelCandidateConfirmationResult,
} from "./candidateConfirmationTypes.ts";
import {
  CandidateConfirmationError,
  toCandidateConfirmationError,
  parsePreparedCandidateConfirmation,
  parseCandidateConfirmationResult,
  parseCancelCandidateConfirmationResult,
} from "./candidateConfirmationTypes.ts";

export type InvokeFunction = (
  command: string,
  args?: Record<string, unknown>,
) => Promise<unknown>;

export interface CandidateConfirmationClient {
  prepareCandidateConfirmation(candidateId: string): Promise<PreparedCandidateConfirmation>;
  confirmCandidateMemory(
    candidateId: string,
    approvalToken: string,
  ): Promise<CandidateConfirmationResult>;
  cancelCandidateConfirmationApproval(
    candidateId: string,
    approvalToken: string,
  ): Promise<CancelCandidateConfirmationResult>;
}

// ── Input Validation ──────────────────────────────────────────────────

function validateCandidateId(candidateId: string): void {
  if (typeof candidateId !== "string" || candidateId.trim().length === 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INVALID_REQUEST",
      "The confirmation request was invalid.",
      "none",
    );
  }
}

function validateApprovalToken(approvalToken: string): void {
  if (typeof approvalToken !== "string" || approvalToken.trim().length === 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INVALID_REQUEST",
      "The confirmation request was invalid.",
      "none",
    );
  }
}

// ── Service Implementation ────────────────────────────────────────────

export class CandidateConfirmationService implements CandidateConfirmationClient {
  private readonly invokeFn: InvokeFunction;

  constructor(invokeFn: InvokeFunction = invoke) {
    this.invokeFn = invokeFn;
  }

  /**
   * Prepare a candidate for confirmation and return a preview plus Approval Token.
   */
  async prepareCandidateConfirmation(
    candidateId: string,
  ): Promise<PreparedCandidateConfirmation> {
    validateCandidateId(candidateId);

    try {
      const response = await this.invokeFn("prepare_candidate_confirmation", {
        request: { candidateId },
      });
      return parsePreparedCandidateConfirmation(response, candidateId);
    } catch (error: unknown) {
      throw toCandidateConfirmationError(error);
    }
  }

  /**
   * Confirm a candidate using its Approval Token, promoting it to a memory.
   */
  async confirmCandidateMemory(
    candidateId: string,
    approvalToken: string,
  ): Promise<CandidateConfirmationResult> {
    validateCandidateId(candidateId);
    validateApprovalToken(approvalToken);

    try {
      const response = await this.invokeFn("confirm_candidate_memory", {
        request: { candidateId, approvalToken },
      });
      return parseCandidateConfirmationResult(response, candidateId);
    } catch (error: unknown) {
      throw toCandidateConfirmationError(error);
    }
  }

  /**
   * Cancel a prepared confirmation, retiring the Approval Token.
   */
  async cancelCandidateConfirmationApproval(
    candidateId: string,
    approvalToken: string,
  ): Promise<CancelCandidateConfirmationResult> {
    validateCandidateId(candidateId);
    validateApprovalToken(approvalToken);

    try {
      const response = await this.invokeFn("cancel_candidate_confirmation_approval", {
        request: { candidateId, approvalToken },
      });
      return parseCancelCandidateConfirmationResult(response, candidateId);
    } catch (error: unknown) {
      throw toCandidateConfirmationError(error);
    }
  }
}

// ── Singleton ─────────────────────────────────────────────────────────

export const candidateConfirmationService = new CandidateConfirmationService();
