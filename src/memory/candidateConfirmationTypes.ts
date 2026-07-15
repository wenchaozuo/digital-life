import type { MemoryKind } from "./types";

// ── Confirmation Requirement ──────────────────────────────────────────

export type CandidateConfirmationRequirement =
  | "standard"
  | "explicitSensitiveApproval";

// ── Candidate Confirmation Outcome ────────────────────────────────────

export type CandidateConfirmationOutcome =
  | "confirmed"
  | "idempotentReplay";

// ── Prepare Response ──────────────────────────────────────────────────
// Aligned with Rust PrepareConfirmationResponse (source is string, not object)

export interface PreparedCandidateConfirmation {
  candidateId: string;
  expectedRevision: number;
  kind: MemoryKind;
  content: string | null;
  summary: string | null;
  isSensitive: boolean;
  source: string;
  confirmationRequirement: CandidateConfirmationRequirement;
  approvalToken: string;
  expiresAt: string;
}

/** Public confirmation preview. Approval Tokens stay private to the Store. */
export type PreparedCandidateConfirmationPreview = Omit<
  PreparedCandidateConfirmation,
  "approvalToken"
>;

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

// ── Recovery Action ───────────────────────────────────────────────────

export type CandidateConfirmationRecoveryAction =
  | "reprepare"
  | "retrySameToken"
  | "retryPrepareLater"
  | "none";

// ── Error Class ───────────────────────────────────────────────────────

export class CandidateConfirmationError extends Error {
  readonly code: CandidateConfirmationErrorCode;
  readonly action: CandidateConfirmationRecoveryAction;
  readonly requiresReprepare: boolean;
  readonly retryAfterMs?: number;

  constructor(
    code: CandidateConfirmationErrorCode,
    message: string,
    action: CandidateConfirmationRecoveryAction,
    options?: { requiresReprepare?: boolean; retryAfterMs?: number },
  ) {
    super(message);
    this.name = "CandidateConfirmationError";
    this.code = code;
    this.action = action;
    this.requiresReprepare = options?.requiresReprepare ?? (action === "reprepare");
    this.retryAfterMs = options?.retryAfterMs;
  }

  get recoverable(): boolean {
    return this.action !== "none";
  }
}

// ── Safe Error Messages ───────────────────────────────────────────────

const SAFE_ERROR_MESSAGES: Record<CandidateConfirmationErrorCode, string> = {
  CANDIDATE_CONFIRMATION_INVALID_REQUEST: "The confirmation request was invalid.",
  CANDIDATE_CONFIRMATION_UNAUTHORIZED_WINDOW: "Confirmation is not available from this window.",
  CANDIDATE_CONFIRMATION_NO_CURRENT_LIFE: "No active life is configured.",
  CANDIDATE_CONFIRMATION_NOT_FOUND: "The candidate is not available for confirmation.",
  CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED: "An approval token is required.",
  CANDIDATE_CONFIRMATION_TOKEN_INVALID: "The approval token is invalid.",
  CANDIDATE_CONFIRMATION_TOKEN_EXPIRED: "The approval token has expired.",
  CANDIDATE_CONFIRMATION_TOKEN_CONSUMED: "The approval token was already used.",
  CANDIDATE_CONFIRMATION_TOKEN_CANCELLED: "The approval token was cancelled.",
  CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT: "A confirmation is already in progress.",
  CANDIDATE_CONFIRMATION_CONTEXT_CHANGED: "The candidate context has changed.",
  CANDIDATE_MEMORY_REVISION_CONFLICT: "The candidate has been modified.",
  CANDIDATE_MEMORY_REQUEST_CONFLICT: "A conflicting confirmation request exists.",
  CANDIDATE_MEMORY_PROHIBITED_CONTENT: "The content cannot be confirmed.",
  CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE: "Storage is temporarily unavailable.",
  CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE: "The service is temporarily unavailable.",
  CANDIDATE_CONFIRMATION_INTERNAL_ERROR: "The confirmation operation failed.",
};

// ── Error Code → Recovery Action ──────────────────────────────────────

function actionForCode(
  code: CandidateConfirmationErrorCode,
): CandidateConfirmationRecoveryAction {
  switch (code) {
    case "CANDIDATE_CONFIRMATION_TOKEN_INVALID":
    case "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED":
    case "CANDIDATE_CONFIRMATION_TOKEN_CONSUMED":
    case "CANDIDATE_CONFIRMATION_TOKEN_CANCELLED":
    case "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED":
    case "CANDIDATE_MEMORY_REVISION_CONFLICT":
    case "CANDIDATE_MEMORY_REQUEST_CONFLICT":
    case "CANDIDATE_MEMORY_PROHIBITED_CONTENT":
      return "reprepare";

    case "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT":
    case "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE":
      return "retrySameToken";

    case "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE":
      return "retryPrepareLater";

    default:
      return "none";
  }
}

function recoveryActionForCode(
  code: CandidateConfirmationErrorCode,
  backendRequiresReprepare?: boolean,
): CandidateConfirmationRecoveryAction {
  const defaultAction = actionForCode(code);

  if (backendRequiresReprepare === true) {
    return "reprepare";
  }

  if (backendRequiresReprepare === false && defaultAction === "reprepare") {
    return "none";
  }

  return defaultAction;
}

// ── Error Mapping ─────────────────────────────────────────────────────

export function toCandidateConfirmationError(error: unknown): CandidateConfirmationError {
  if (error instanceof CandidateConfirmationError) {
    return error;
  }

  if (isRecord(error)) {
    const rawCode = typeof error.code === "string" ? error.code : undefined;
    const code = isValidErrorCode(rawCode) ? rawCode : "CANDIDATE_CONFIRMATION_INTERNAL_ERROR";
    const message = SAFE_ERROR_MESSAGES[code];

    const backendRequiresReprepare =
      typeof error.requiresReprepare === "boolean" ? error.requiresReprepare : undefined;
    const action = recoveryActionForCode(code, backendRequiresReprepare);

    const retryAfterMs = parseRetryAfterMs(
      isRecord(error) && "retryAfterMs" in error ? error.retryAfterMs : undefined,
    );

    return new CandidateConfirmationError(code, message, action, {
      requiresReprepare: backendRequiresReprepare ?? (action === "reprepare"),
      retryAfterMs,
    });
  }

  return new CandidateConfirmationError(
    "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
    SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
    "none",
  );
}

function parseRetryAfterMs(value: unknown): number | undefined {
  if (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value > 0
  ) {
    return value;
  }
  return undefined;
}

function isValidErrorCode(code: string | undefined): code is CandidateConfirmationErrorCode {
  if (!code) return false;
  return VALID_ERROR_CODES.has(code);
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

// ── Runtime Response Parsers ──────────────────────────────────────────

const VALID_MEMORY_KINDS = new Set([
  "experience", "preference", "fact", "relationship", "goal", "skill", "other",
]);

const VALID_REQUIREMENTS = new Set(["standard", "explicitSensitiveApproval"]);
const VALID_OUTCOMES = new Set(["confirmed", "idempotentReplay"]);

// Token format: 64 lowercase hex chars (32 bytes)
const TOKEN_PATTERN = /^[0-9a-f]{64}$/;

export function parsePreparedCandidateConfirmation(
  value: unknown,
  expectedCandidateId: string,
): PreparedCandidateConfirmation {
  if (!isRecord(value) || Array.isArray(value)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const candidateId = value.candidateId;
  if (typeof candidateId !== "string" || candidateId.length === 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }
  if (candidateId !== expectedCandidateId) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const expectedRevision = value.expectedRevision;
  if (typeof expectedRevision !== "number" || !Number.isSafeInteger(expectedRevision) || expectedRevision < 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const kind = value.kind;
  if (typeof kind !== "string" || !VALID_MEMORY_KINDS.has(kind)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  // content and summary: must be string or null
  const content = value.content;
  if (content !== null && typeof content !== "string") {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const summary = value.summary;
  if (summary !== null && typeof summary !== "string") {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  if (typeof value.isSensitive !== "boolean") {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  // source is a plain string (not an object)
  if (typeof value.source !== "string") {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const confirmationRequirement = value.confirmationRequirement;
  if (typeof confirmationRequirement !== "string" || !VALID_REQUIREMENTS.has(confirmationRequirement)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const approvalToken = value.approvalToken;
  if (typeof approvalToken !== "string" || !TOKEN_PATTERN.test(approvalToken)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const expiresAt = value.expiresAt;
  if (typeof expiresAt !== "string") {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }
  const parsedTime = Date.parse(expiresAt);
  if (!Number.isFinite(parsedTime)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  return {
    candidateId,
    expectedRevision,
    kind: kind as MemoryKind,
    content,
    summary,
    isSensitive: value.isSensitive as boolean,
    source: value.source as string,
    confirmationRequirement: confirmationRequirement as CandidateConfirmationRequirement,
    approvalToken,
    expiresAt,
  };
}

export function parseCandidateConfirmationResult(
  value: unknown,
  expectedCandidateId: string,
): CandidateConfirmationResult {
  if (!isRecord(value) || Array.isArray(value)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const candidateId = value.candidateId;
  if (typeof candidateId !== "string" || candidateId.length === 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }
  if (candidateId !== expectedCandidateId) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const confirmedMemoryId = value.confirmedMemoryId;
  if (typeof confirmedMemoryId !== "string" || confirmedMemoryId.length === 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const outcome = value.outcome;
  if (typeof outcome !== "string" || !VALID_OUTCOMES.has(outcome)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  return {
    candidateId,
    confirmedMemoryId,
    outcome: outcome as CandidateConfirmationOutcome,
  };
}

export function parseCancelCandidateConfirmationResult(
  value: unknown,
  expectedCandidateId: string,
): CancelCandidateConfirmationResult {
  if (!isRecord(value) || Array.isArray(value)) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  const candidateId = value.candidateId;
  if (typeof candidateId !== "string" || candidateId.length === 0) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }
  if (candidateId !== expectedCandidateId) {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  if (typeof value.cancelled !== "boolean") {
    throw new CandidateConfirmationError(
      "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
      SAFE_ERROR_MESSAGES.CANDIDATE_CONFIRMATION_INTERNAL_ERROR,
      "none",
    );
  }

  return {
    candidateId,
    cancelled: value.cancelled,
  };
}
