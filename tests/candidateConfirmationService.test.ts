import test from "node:test";
import assert from "node:assert/strict";

import {
  CandidateConfirmationError,
  toCandidateConfirmationError,
  parsePreparedCandidateConfirmation,
  parseCandidateConfirmationResult,
  parseCancelCandidateConfirmationResult,
  type PreparedCandidateConfirmation,
  type CandidateConfirmationResult,
  type CancelCandidateConfirmationResult,
} from "../src/memory/candidateConfirmationTypes.ts";
import {
  CandidateConfirmationService,
  type InvokeFunction,
} from "../src/memory/candidateConfirmationService.ts";

// ── Invoke Mock ───────────────────────────────────────────────────────

interface InvokeCall {
  command: string;
  args: Record<string, unknown>;
}

function createInvokeStub(response: unknown): {
  calls: InvokeCall[];
  invokeFn: InvokeFunction;
} {
  const calls: InvokeCall[] = [];
  const invokeFn: InvokeFunction = async (command, args) => {
    calls.push({ command, args: args ?? {} });
    return response;
  };
  return { calls, invokeFn };
}

// ── Valid Response Factories ──────────────────────────────────────────

function validPrepareResponse(candidateId: string = "c1"): Record<string, unknown> {
  return {
    candidateId,
    expectedRevision: 1,
    kind: "preference",
    content: "Test content",
    summary: "Test summary",
    isSensitive: false,
    source: "conversation",
    confirmationRequirement: "standard",
    approvalToken: "a".repeat(64),
    expiresAt: new Date(Date.now() + 300000).toISOString(),
  };
}

function validConfirmResponse(candidateId: string = "c1"): Record<string, unknown> {
  return {
    candidateId,
    confirmedMemoryId: "mem-123",
    outcome: "confirmed",
  };
}

function validCancelResponse(candidateId: string = "c1"): Record<string, unknown> {
  return {
    candidateId,
    cancelled: true,
  };
}

// ── Prepare Response Parsing Tests ────────────────────────────────────

test("parsePreparedCandidateConfirmation: valid response succeeds", () => {
  const raw = validPrepareResponse();
  const result = parsePreparedCandidateConfirmation(raw, "c1");
  assert.equal(result.candidateId, "c1");
  assert.equal(result.source, "conversation");
  assert.equal(typeof result.source, "string");
  assert.equal(result.kind, "preference");
  assert.equal(result.approvalToken, "a".repeat(64));
});

test("parsePreparedCandidateConfirmation: source must be string not object", () => {
  const raw = validPrepareResponse();
  raw.source = { sourceType: "conversation", inferenceStatus: "completed" };
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError && err.code === "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
  );
});

test("parsePreparedCandidateConfirmation: rejects null root", () => {
  assert.throws(
    () => parsePreparedCandidateConfirmation(null, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects array", () => {
  assert.throws(
    () => parsePreparedCandidateConfirmation([], "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects candidateId mismatch", () => {
  const raw = validPrepareResponse("c2");
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects empty candidateId", () => {
  const raw = validPrepareResponse();
  raw.candidateId = "";
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, ""),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects negative expectedRevision", () => {
  const raw = validPrepareResponse();
  raw.expectedRevision = -1;
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects non-integer expectedRevision", () => {
  const raw = validPrepareResponse();
  raw.expectedRevision = 1.5;
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects unknown kind", () => {
  const raw = validPrepareResponse();
  raw.kind = "unknown_kind";
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects non-boolean isSensitive", () => {
  const raw = validPrepareResponse();
  raw.isSensitive = "true";
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects invalid confirmationRequirement", () => {
  const raw = validPrepareResponse();
  raw.confirmationRequirement = "invalid";
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects malformed token", () => {
  const raw = validPrepareResponse();
  raw.approvalToken = "not-hex";
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects empty token", () => {
  const raw = validPrepareResponse();
  raw.approvalToken = "";
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects non-string token", () => {
  const raw = validPrepareResponse();
  raw.approvalToken = 123;
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects invalid expiresAt", () => {
  const raw = validPrepareResponse();
  raw.expiresAt = "not-a-date";
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: rejects non-string expiresAt", () => {
  const raw = validPrepareResponse();
  raw.expiresAt = 12345;
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: null content is valid", () => {
  const raw = validPrepareResponse();
  raw.content = null;
  const result = parsePreparedCandidateConfirmation(raw, "c1");
  assert.equal(result.content, null);
});

test("parsePreparedCandidateConfirmation: null summary is valid", () => {
  const raw = validPrepareResponse();
  raw.summary = null;
  const result = parsePreparedCandidateConfirmation(raw, "c1");
  assert.equal(result.summary, null);
});

test("parsePreparedCandidateConfirmation: rejects non-string non-null content", () => {
  const raw = validPrepareResponse();
  raw.content = 123;
  assert.throws(
    () => parsePreparedCandidateConfirmation(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parsePreparedCandidateConfirmation: explicitSensitiveApproval is valid", () => {
  const raw = validPrepareResponse();
  raw.confirmationRequirement = "explicitSensitiveApproval";
  const result = parsePreparedCandidateConfirmation(raw, "c1");
  assert.equal(result.confirmationRequirement, "explicitSensitiveApproval");
});

// ── Confirm Response Parsing Tests ────────────────────────────────────

test("parseCandidateConfirmationResult: valid confirmed outcome", () => {
  const raw = validConfirmResponse();
  const result = parseCandidateConfirmationResult(raw, "c1");
  assert.equal(result.candidateId, "c1");
  assert.equal(result.confirmedMemoryId, "mem-123");
  assert.equal(result.outcome, "confirmed");
});

test("parseCandidateConfirmationResult: valid idempotentReplay outcome", () => {
  const raw = validConfirmResponse();
  raw.outcome = "idempotentReplay";
  const result = parseCandidateConfirmationResult(raw, "c1");
  assert.equal(result.outcome, "idempotentReplay");
});

test("parseCandidateConfirmationResult: rejects candidateId mismatch", () => {
  const raw = validConfirmResponse("c2");
  assert.throws(
    () => parseCandidateConfirmationResult(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parseCandidateConfirmationResult: rejects empty confirmedMemoryId", () => {
  const raw = validConfirmResponse();
  raw.confirmedMemoryId = "";
  assert.throws(
    () => parseCandidateConfirmationResult(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parseCandidateConfirmationResult: rejects invalid outcome", () => {
  const raw = validConfirmResponse();
  raw.outcome = "invalid";
  assert.throws(
    () => parseCandidateConfirmationResult(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parseCandidateConfirmationResult: rejects null root", () => {
  assert.throws(
    () => parseCandidateConfirmationResult(null, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

// ── Cancel Response Parsing Tests ─────────────────────────────────────

test("parseCancelCandidateConfirmationResult: valid response", () => {
  const raw = validCancelResponse();
  const result = parseCancelCandidateConfirmationResult(raw, "c1");
  assert.equal(result.candidateId, "c1");
  assert.equal(result.cancelled, true);
});

test("parseCancelCandidateConfirmationResult: false cancelled is valid", () => {
  const raw = validCancelResponse();
  raw.cancelled = false;
  const result = parseCancelCandidateConfirmationResult(raw, "c1");
  assert.equal(result.cancelled, false);
});

test("parseCancelCandidateConfirmationResult: rejects candidateId mismatch", () => {
  const raw = validCancelResponse("c2");
  assert.throws(
    () => parseCancelCandidateConfirmationResult(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parseCancelCandidateConfirmationResult: rejects non-boolean cancelled", () => {
  const raw = validCancelResponse();
  raw.cancelled = "true";
  assert.throws(
    () => parseCancelCandidateConfirmationResult(raw, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

test("parseCancelCandidateConfirmationResult: rejects null root", () => {
  assert.throws(
    () => parseCancelCandidateConfirmationResult(null, "c1"),
    (err: unknown) => err instanceof CandidateConfirmationError,
  );
});

// ── Error Mapping Tests ───────────────────────────────────────────────

test("toCandidateConfirmationError: 17 error codes recognized", () => {
  const codes = [
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
  ];

  for (const code of codes) {
    const err = toCandidateConfirmationError({ code });
    assert.ok(err instanceof CandidateConfirmationError, `Failed for ${code}`);
    assert.equal(err.code, code, `Code mismatch for ${code}`);
  }
});

test("toCandidateConfirmationError: reprepare action codes", () => {
  for (const code of [
    "CANDIDATE_CONFIRMATION_TOKEN_INVALID",
    "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
    "CANDIDATE_CONFIRMATION_TOKEN_CONSUMED",
    "CANDIDATE_CONFIRMATION_TOKEN_CANCELLED",
    "CANDIDATE_CONFIRMATION_CONTEXT_CHANGED",
    "CANDIDATE_MEMORY_REVISION_CONFLICT",
    "CANDIDATE_MEMORY_REQUEST_CONFLICT",
    "CANDIDATE_MEMORY_PROHIBITED_CONTENT",
  ]) {
    const err = toCandidateConfirmationError({ code });
    assert.equal(err.action, "reprepare", `${code} should be reprepare`);
    assert.equal(err.requiresReprepare, true, `${code} requiresReprepare`);
  }
});

test("toCandidateConfirmationError: retrySameToken action codes", () => {
  for (const code of [
    "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT",
    "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
  ]) {
    const err = toCandidateConfirmationError({ code });
    assert.equal(err.action, "retrySameToken", `${code} should be retrySameToken`);
    assert.equal(err.requiresReprepare, false, `${code} not requiresReprepare`);
  }
});

test("toCandidateConfirmationError: retryPrepareLater action", () => {
  const err = toCandidateConfirmationError({ code: "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE" });
  assert.equal(err.action, "retryPrepareLater");
});

test("toCandidateConfirmationError: none action codes", () => {
  for (const code of [
    "CANDIDATE_CONFIRMATION_INVALID_REQUEST",
    "CANDIDATE_CONFIRMATION_UNAUTHORIZED_WINDOW",
    "CANDIDATE_CONFIRMATION_NO_CURRENT_LIFE",
    "CANDIDATE_CONFIRMATION_NOT_FOUND",
    "CANDIDATE_CONFIRMATION_APPROVAL_REQUIRED",
    "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
  ]) {
    const err = toCandidateConfirmationError({ code });
    assert.equal(err.action, "none", `${code} should be none`);
    assert.equal(err.recoverable, false, `${code} not recoverable`);
  }
});

test("toCandidateConfirmationError: backend requiresReprepare takes priority", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_NOT_FOUND",
    requiresReprepare: true,
  });
  assert.equal(err.action, "reprepare");
  assert.equal(err.requiresReprepare, true);
});

test("toCandidateConfirmationError: backend false overrides a local reprepare default", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
    requiresReprepare: false,
  });
  assert.equal(err.action, "none");
  assert.equal(err.requiresReprepare, false);
});

test("toCandidateConfirmationError: backend false preserves non-reprepare recovery actions", () => {
  const storage = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
    requiresReprepare: false,
  });
  const temporary = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE",
    requiresReprepare: false,
  });
  assert.equal(storage.action, "retrySameToken");
  assert.equal(temporary.action, "retryPrepareLater");
});

test("toCandidateConfirmationError: unknown code maps to INTERNAL_ERROR", () => {
  const err = toCandidateConfirmationError({ code: "UNKNOWN_CODE" });
  assert.equal(err.code, "CANDIDATE_CONFIRMATION_INTERNAL_ERROR");
  assert.equal(err.action, "none");
});

test("toCandidateConfirmationError: non-object maps to INTERNAL_ERROR", () => {
  const err = toCandidateConfirmationError("string error");
  assert.equal(err.code, "CANDIDATE_CONFIRMATION_INTERNAL_ERROR");
  assert.equal(err.action, "none");
});

test("toCandidateConfirmationError: safe message, no raw error leaked", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
    message: "SECRET_TOKEN_LEAKED abc123",
  });
  assert.equal(err.message, "The approval token has expired.");
  assert.ok(!err.message.includes("SECRET"));
});

test("toCandidateConfirmationError: unknown error uses safe generic message", () => {
  const err = toCandidateConfirmationError({ code: "UNKNOWN" });
  assert.equal(err.message, "The confirmation operation failed.");
});

// ── retryAfterMs Validation Tests ─────────────────────────────────────

test("retryAfterMs: accepts valid positive integer", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
    retryAfterMs: 250,
  });
  assert.equal(err.retryAfterMs, 250);
});

test("retryAfterMs: rejects NaN", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
    retryAfterMs: NaN,
  });
  assert.equal(err.retryAfterMs, undefined);
});

test("retryAfterMs: rejects Infinity", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
    retryAfterMs: Infinity,
  });
  assert.equal(err.retryAfterMs, undefined);
});

test("retryAfterMs: rejects negative", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
    retryAfterMs: -100,
  });
  assert.equal(err.retryAfterMs, undefined);
});

test("retryAfterMs: rejects float", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
    retryAfterMs: 250.5,
  });
  assert.equal(err.retryAfterMs, undefined);
});

test("retryAfterMs: rejects zero", () => {
  const err = toCandidateConfirmationError({
    code: "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
    retryAfterMs: 0,
  });
  assert.equal(err.retryAfterMs, undefined);
});

// ── recoverable Compat Tests ──────────────────────────────────────────

test("recoverable: true for reprepare", () => {
  const err = new CandidateConfirmationError(
    "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
    "expired",
    "reprepare",
  );
  assert.equal(err.recoverable, true);
});

test("recoverable: true for retrySameToken", () => {
  const err = new CandidateConfirmationError(
    "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
    "unavailable",
    "retrySameToken",
  );
  assert.equal(err.recoverable, true);
});

test("recoverable: false for none", () => {
  const err = new CandidateConfirmationError(
    "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
    "internal",
    "none",
  );
  assert.equal(err.recoverable, false);
});

// ── Service invoke pattern tests ──────────────────────────────────────

test("service: prepare invokes the exact request wrapper and omits forbidden fields", async () => {
  const stub = createInvokeStub(validPrepareResponse("candidate-a"));
  const service = new CandidateConfirmationService(stub.invokeFn);

  await service.prepareCandidateConfirmation("candidate-a");

  assert.deepEqual(stub.calls, [{
    command: "prepare_candidate_confirmation",
    args: { request: { candidateId: "candidate-a" } },
  }]);
  const request = stub.calls[0].args.request as Record<string, unknown>;
  for (const forbidden of [
    "lifeId", "expectedRevision", "requestId", "isSensitive",
    "sensitiveConfirmed", "userConfirmed", "Grant",
  ]) {
    assert.equal(forbidden in request, false, `${forbidden} must not be sent`);
  }
});

test("service: confirm invokes the exact request wrapper", async () => {
  const token = "b".repeat(64);
  const stub = createInvokeStub(validConfirmResponse("candidate-b"));
  const service = new CandidateConfirmationService(stub.invokeFn);

  await service.confirmCandidateMemory("candidate-b", token);

  assert.deepEqual(stub.calls, [{
    command: "confirm_candidate_memory",
    args: { request: { candidateId: "candidate-b", approvalToken: token } },
  }]);
});

test("service: cancel invokes the exact request wrapper", async () => {
  const token = "c".repeat(64);
  const stub = createInvokeStub(validCancelResponse("candidate-c"));
  const service = new CandidateConfirmationService(stub.invokeFn);

  await service.cancelCandidateConfirmationApproval("candidate-c", token);

  assert.deepEqual(stub.calls, [{
    command: "cancel_candidate_confirmation_approval",
    args: { request: { candidateId: "candidate-c", approvalToken: token } },
  }]);
});
