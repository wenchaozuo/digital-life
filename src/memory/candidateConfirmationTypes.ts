import type { MemoryKind } from "./types";

// ── Confirmation Requirement ──────────────────────────────────────────

export type ConfirmationRequirement =
  | "standard"
  | "explicitSensitiveApproval";

// ── Candidate Confirmation Outcome ────────────────────────────────────

export type CandidateConfirmationOutcome =
  | "confirmed"
  | "idempotentReplay";

// ── Source Summary ────────────────────────────────────────────────────

export interface CandidateConfirmationSourceSummary {
  sourceType: string;
  inferenceStatus: string;
}

// ── Prepare Response ──────────────────────────────────────────────────

export interface PreparedCandidateConfirmation {
  candidateId: string;
  expectedRevision: number;
  kind: MemoryKind;
  content: string | null;
  summary: string | null;
  isSensitive: boolean;
  source: CandidateConfirmationSourceSummary;
  confirmationRequirement: ConfirmationRequirement;
  approvalToken: string;
  expiresAt: string;
}

// ── Confirm Response ──────────────────────────────────────────────────

export interface CandidateConfirmationResult {
  candidateId: string;
  confirmedMemoryId: string;
  outcome: CandidateConfirmationOutcome;
}

// ── Cancel Response ───────────────────────────────────────────────────

export interface CancelCandidateConfirmationResult {
  candidateId: string;
  cancelled: boolean;
}

// ── Error Codes ───────────────────────────────────────────────────────

export type CandidateConfirmationErrorCode =
  | "CANDIDATE_CONFIRMATION_INVALID_REQUEST"
  | "CANDIDATE_CONFIRMATION_UNAUTHORIZED_WINDOW"
  | "CANDIDATE_CONFIRMATION_NO_CURRENT_LIFE"
  | "CANDIDATE_CONFIRMATION_NOT_FOUND"
  | "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED"
  | "CANDIDATE_CONFIRMATION_TOKEN_INVALID"
  | "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED"
  | "CANDIDATE_CONFIRMATION_TOKEN_CONSUMED"
  | "CANDIDATE_CONFIRMATION_TOKEN_CANCELLED"
  | "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT"
  | "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED"
  | "CANDIDATE_MEMORY_REVISION_CONFLICT"
  | "CANDIDATE_MEMORY_REQUEST_CONFLICT"
  | "CANDIDATE_MEMORY_PROHIBITED_CONTENT"
  | "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE"
  | "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE"
  | "CANDIDATE_CONFIRMATION_INTERNAL_ERROR";

// ── Error Details ─────────────────────────────────────────────────────

export interface CandidateConfirmationErrorDetails {
  requiresReprepare?: boolean;
  retryAfterMs?: number;
}

// ── Error Class ───────────────────────────────────────────────────────

export class CandidateConfirmationError extends Error {
  readonly code: CandidateConfirmationErrorCode;
  readonly recoverable: boolean;
  readonly details?: CandidateConfirmationErrorDetails;

  constructor(
    code: CandidateConfirmationErrorCode,
    message: string,
    recoverable: boolean,
    details?: CandidateConfirmationErrorDetails,
  ) {
    super(message);
    this.name = "CandidateConfirmationError";
    this.code = code;
    this.recoverable = recoverable;
    this.details = details;
  }
}

// ── Error Code Constants ──────────────────────────────────────────────

const REPREPARE_CODES = new Set<CandidateConfirmationErrorCode>([
  "CANDIDATE_CONFIRMATION_TOKEN_INVALID",
  "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
  "CANDIDATE_CONFIRMATION_TOKEN_CANCELLED",
  "CANDIDATE_CONFIRMATION_TOKEN_CONSUMED",
  "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED",
  "CANDIDATE_MEMORY_REVISION_CONFLICT",
  "CANDIDATE_MEMORY_REQUEST_CONFLICT",
  "CANDIDATE_MEMORY_PROHIBITED_CONTENT",
]);

const RETRYABLE_CODES = new Set<CandidateConfirmationErrorCode>([
  "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
  "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT",
]);

const NON_RECOVERABLE_CODES = new Set<CandidateConfirmationErrorCode>([
  "CANDIDATE_CONFIRMATION_INVALID_REQUEST",
  "CANDIDATE_CONFIRMATION_UNAUTHORIZED_WINDOW",
  "CANDIDATE_CONFIRMATION_NO_CURRENT_LIFE",
  "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
]);

// ── Error Mapping ─────────────────────────────────────────────────────

export function isReprepareRequired(error: CandidateConfirmationError): boolean {
  if (error.details?.requiresReprepare !== undefined) {
    return error.details.requiresReprepare;
  }
  return REPREPARE_CODES.has(error.code);
}

export function isRetryable(error: CandidateConfirmationError): boolean {
  return RETRYABLE_CODES.has(error.code);
}

export function toCandidateConfirmationError(error: unknown): CandidateConfirmationError {
  if (error instanceof CandidateConfirmationError) {
    return error;
  }

  if (isRecord(error)) {
    const rawCode = typeof error.code === "string" ? error.code : undefined;
    const code = isValidErrorCode(rawCode) ? rawCode : "CANDIDATE_CONFIRMATION_INTERNAL_ERROR";
    const message =
      typeof error.message === "string"
        ? error.message
        : "The candidate confirmation operation could not be completed.";
    const recoverable = !NON_RECOVERABLE_CODES.has(code);
    const details: CandidateConfirmationErrorDetails = {};

    if (typeof error.requiresReprepare === "boolean") {
      details.requiresReprepare = error.requiresReprepare;
    }
    if (typeof error.retryAfterMs === "number" && error.retryAfterMs > 0) {
      details.retryAfterMs = error.retryAfterMs;
    }

    return new CandidateConfirmationError(code, message, recoverable, details);
  }

  return new CandidateConfirmationError(
    "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
    "The candidate confirmation operation could not be completed.",
    false,
  );
}

function isValidErrorCode(code: string | undefined): code is CandidateConfirmationErrorCode {
  if (!code) return false;
  return VALID_ERROR_CODES.has(code as CandidateConfirmationErrorCode);
}

const VALID_ERROR_CODES = new Set<string>([
  "CANDIDATE_CONFIRMATION_INVALID_REQUEST",
  "CANDIDATE_CONFIRMATION_UNAUTHORIZED_WINDOW",
  "CANDIDATE_CONFIRMATION_NO_CURRENT_LIFE",
  "CANDIDATE_CONFIRMATION_NOT_FOUND",
  "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED",
  "CANDIDATE_CONFIRMATION_TOKEN_INVALID",
  "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
  "CANDIDATE_CONFIRMATION_TOKEN_CONSUMED",
  "CANDIDATE_CONFIRMATION_TOKEN_CANCELLED",
  "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT",
  "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED",
  "CANDIDATE_MEMORY_REVISION_CONFLICT",
  "CANDIDATE_MEMORY_REQUEST_CONFLICT",
  "CANDIDATE_MEMORY_PROHIBITED_CONTENT",
  "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
  "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE",
  "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
