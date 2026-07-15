import test from "node:test";
import assert from "node:assert/strict";
import { createPinia, setActivePinia } from "pinia";

import { createCandidateConfirmationStore } from "../src/stores/candidateConfirmation.ts";
import type { CandidateConfirmationClient } from "../src/memory/candidateConfirmationService.ts";
import type {
  CandidateConfirmationResult,
  CancelCandidateConfirmationResult,
  PreparedCandidateConfirmation,
} from "../src/memory/candidateConfirmationTypes.ts";
import { CandidateConfirmationError } from "../src/memory/candidateConfirmationTypes.ts";

interface Deferred<T> {
  promise: Promise<T>;
  resolve(value: T): void;
  reject(reason?: unknown): void;
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function prepared(candidateId: string, approvalToken = "a".repeat(64)): PreparedCandidateConfirmation {
  return {
    candidateId,
    expectedRevision: 1,
    kind: "preference",
    content: "content",
    summary: "summary",
    isSensitive: false,
    source: "conversation",
    confirmationRequirement: "standard",
    approvalToken,
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  };
}

function confirmed(candidateId: string): CandidateConfirmationResult {
  return { candidateId, confirmedMemoryId: "memory-1", outcome: "confirmed" };
}

function cancelled(candidateId: string, value = true): CancelCandidateConfirmationResult {
  return { candidateId, cancelled: value };
}

function setup(service: CandidateConfirmationClient) {
  setActivePinia(createPinia());
  return createCandidateConfirmationStore(service)();
}

test("store: prepare holds token privately and confirm consumes it", async () => {
  const calls: Array<[string, string, string?]> = [];
  const store = setup({
    prepareCandidateConfirmation: async (id) => prepared(id, "b".repeat(64)),
    confirmCandidateMemory: async (id, token) => {
      calls.push(["confirm", id, token]);
      return confirmed(id);
    },
    cancelCandidateConfirmationApproval: async (id, token) => {
      calls.push(["cancel", id, token]);
      return cancelled(id);
    },
  });

  await store.prepare("candidate-a");
  assert.equal(store.phase, "prepared");
  assert.equal(store.prepared?.candidateId, "candidate-a");
  assert.equal("approvalToken" in (store.prepared ?? {}), false);
  assert.equal("approvalToken" in store, false);
  assert.equal(store.canConfirm, true);

  await store.confirm("candidate-a");
  assert.deepEqual(calls, [["confirm", "candidate-a", "b".repeat(64)]]);
  assert.equal(store.phase, "succeeded");
  assert.equal(store.prepared, null);
  assert.equal(store.result?.candidateId, "candidate-a");
});

test("store: candidate binding prevents mismatched confirm and cancel", async () => {
  let confirmCalls = 0;
  let cancelCalls = 0;
  const store = setup({
    prepareCandidateConfirmation: async (id) => prepared(id),
    confirmCandidateMemory: async (id) => { confirmCalls += 1; return confirmed(id); },
    cancelCandidateConfirmationApproval: async (id) => { cancelCalls += 1; return cancelled(id); },
  });
  await store.prepare("candidate-a");

  await assert.rejects(store.confirm("candidate-b"));
  await assert.rejects(store.cancel("candidate-b"));
  assert.equal(confirmCalls, 0);
  assert.equal(cancelCalls, 0);
  assert.equal(store.phase, "prepared");
  assert.equal(store.prepared?.candidateId, "candidate-a");
});

test("store: concurrent prepare, confirm, and cancel transitions are rejected", async () => {
  const prepareDeferred = deferred<PreparedCandidateConfirmation>();
  const confirmDeferred = deferred<CandidateConfirmationResult>();
  const cancelDeferred = deferred<CancelCandidateConfirmationResult>();
  let initialPreparePending = true;
  let cancelCalls = 0;
  let confirmCalls = 0;
  const store = setup({
    prepareCandidateConfirmation: async (id) => {
      if (initialPreparePending) return prepareDeferred.promise;
      return prepared(id);
    },
    confirmCandidateMemory: async () => { confirmCalls += 1; return confirmDeferred.promise; },
    cancelCandidateConfirmationApproval: async () => { cancelCalls += 1; return cancelDeferred.promise; },
  });

  const preparing = store.prepare("candidate-a");
  await assert.rejects(store.cancel("candidate-a"));
  await assert.rejects(store.prepare("candidate-b"));
  assert.equal(cancelCalls, 0);
  prepareDeferred.resolve(prepared("candidate-a"));
  await preparing;
  initialPreparePending = false;

  const confirming = store.confirm("candidate-a");
  await assert.rejects(store.cancel("candidate-a"));
  await assert.rejects(store.confirm("candidate-a"));
  assert.equal(cancelCalls, 0);
  assert.equal(confirmCalls, 1);
  confirmDeferred.resolve(confirmed("candidate-a"));
  await confirming;

  await store.prepare("candidate-c");
  const cancelling = store.cancel("candidate-c");
  await assert.rejects(store.confirm("candidate-c"));
  await assert.rejects(store.cancel("candidate-c"));
  assert.equal(confirmCalls, 1);
  cancelDeferred.resolve(cancelled("candidate-c"));
  await cancelling;
  assert.equal(store.phase, "idle");
});

test("store: clear prevents a stale prepare success or failure from writing state", async () => {
  const first = deferred<PreparedCandidateConfirmation>();
  const second = deferred<PreparedCandidateConfirmation>();
  let count = 0;
  const store = setup({
    prepareCandidateConfirmation: async () => (++count === 1 ? first.promise : second.promise),
    confirmCandidateMemory: async (id) => confirmed(id),
    cancelCandidateConfirmationApproval: async (id) => cancelled(id),
  });

  const prepareA = store.prepare("candidate-a");
  store.clearCandidateConfirmation();
  first.resolve(prepared("candidate-a"));
  await prepareA;
  assert.equal(store.phase, "idle");

  const prepareB = store.prepare("candidate-b");
  second.resolve(prepared("candidate-b"));
  await prepareB;
  assert.equal(store.phase, "prepared");
  assert.equal(store.prepared?.candidateId, "candidate-b");

  const failingPrepare = deferred<PreparedCandidateConfirmation>();
  const failingStore = setup({
    prepareCandidateConfirmation: async () => failingPrepare.promise,
    confirmCandidateMemory: async (id) => confirmed(id),
    cancelCandidateConfirmationApproval: async (id) => cancelled(id),
  });
  const failingOperation = failingStore.prepare("candidate-c");
  failingStore.clearCandidateConfirmation();
  failingPrepare.reject(new Error("stale prepare failure"));
  await failingOperation;
  assert.equal(failingStore.phase, "idle");
  assert.equal(failingStore.error, null);
});

test("store: clear prevents a stale confirm or cancel response from overwriting a newer prepare", async () => {
  const confirmDeferred = deferred<CandidateConfirmationResult>();
  const cancelDeferred = deferred<CancelCandidateConfirmationResult>();
  let confirmPending = true;
  let cancelPending = false;
  const store = setup({
    prepareCandidateConfirmation: async (id) => prepared(id, id === "candidate-a" ? "a".repeat(64) : "b".repeat(64)),
    confirmCandidateMemory: async (id) => confirmPending ? confirmDeferred.promise : confirmed(id),
    cancelCandidateConfirmationApproval: async (id) => cancelPending ? cancelDeferred.promise : cancelled(id),
  });

  await store.prepare("candidate-a");
  const confirming = store.confirm("candidate-a");
  store.clearCandidateConfirmation();
  await store.prepare("candidate-b");
  confirmDeferred.resolve(confirmed("candidate-a"));
  await confirming;
  assert.equal(store.phase, "prepared");
  assert.equal(store.prepared?.candidateId, "candidate-b");

  store.clearCandidateConfirmation();
  await store.prepare("candidate-a");
  confirmPending = false;
  cancelPending = true;
  const cancelling = store.cancel("candidate-a");
  store.clearCandidateConfirmation();
  await store.prepare("candidate-b");
  cancelDeferred.resolve(cancelled("candidate-a"));
  await cancelling;
  assert.equal(store.phase, "prepared");
  assert.equal(store.prepared?.candidateId, "candidate-b");

  const failedConfirm = deferred<CandidateConfirmationResult>();
  const failedCancel = deferred<CancelCandidateConfirmationResult>();
  let failureMode: "confirm" | "cancel" = "confirm";
  const failureStore = setup({
    prepareCandidateConfirmation: async (id) => prepared(id),
    confirmCandidateMemory: async () => failedConfirm.promise,
    cancelCandidateConfirmationApproval: async () => failedCancel.promise,
  });
  await failureStore.prepare("candidate-a");
  const failedConfirmOperation = failureStore.confirm("candidate-a");
  failureStore.clearCandidateConfirmation();
  await failureStore.prepare("candidate-b");
  failedConfirm.reject(new Error("stale confirm failure"));
  await failedConfirmOperation;
  assert.equal(failureStore.phase, "prepared");
  assert.equal(failureStore.prepared?.candidateId, "candidate-b");

  failureMode = "cancel";
  failureStore.clearCandidateConfirmation();
  await failureStore.prepare("candidate-a");
  const failedCancelOperation = failureStore.cancel("candidate-a");
  failureStore.clearCandidateConfirmation();
  await failureStore.prepare("candidate-b");
  failedCancel.reject(new Error(`${failureMode} failure`));
  await failedCancelOperation;
  assert.equal(failureStore.phase, "prepared");
  assert.equal(failureStore.prepared?.candidateId, "candidate-b");
});

test("store: retry-same-token retains authorization, while reprepare clears it", async () => {
  const tokens: string[] = [];
  let attempt = 0;
  const store = setup({
    prepareCandidateConfirmation: async (id) => prepared(id, "d".repeat(64)),
    confirmCandidateMemory: async (id, token) => {
      tokens.push(token);
      attempt += 1;
      if (attempt === 1) {
        throw new CandidateConfirmationError(
          "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE", "", "retrySameToken",
        );
      }
      if (attempt === 2) {
        throw new CandidateConfirmationError(
          "CANDIDATE_CONFIRMATION_TOKEN_IN_FLIGHT", "", "retrySameToken",
        );
      }
      if (attempt === 3) {
        throw new CandidateConfirmationError(
          "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED", "", "reprepare",
        );
      }
      return confirmed(id);
    },
    cancelCandidateConfirmationApproval: async (id) => cancelled(id),
  });

  await store.prepare("candidate-a");
  await store.confirm("candidate-a");
  assert.equal(store.phase, "prepared");
  await store.confirm("candidate-a");
  assert.equal(store.phase, "prepared");
  await store.confirm("candidate-a");
  assert.equal(store.phase, "failed");
  assert.equal(store.prepared, null);
  assert.equal(tokens[0], tokens[1]);
  assert.equal(tokens[1], tokens[2]);
});

test("store: cancel false or rejection clears local authorization and reports failure", async () => {
  let mode: "false" | "reject" = "false";
  const store = setup({
    prepareCandidateConfirmation: async (id) => prepared(id),
    confirmCandidateMemory: async (id) => confirmed(id),
    cancelCandidateConfirmationApproval: async (id) => {
      if (mode === "reject") throw new Error("backend detail must not leak");
      return cancelled(id, false);
    },
  });

  await store.prepare("candidate-a");
  await store.cancel("candidate-a");
  assert.equal(store.phase, "failed");
  assert.equal(store.prepared, null);
  assert.match(store.error?.message ?? "", /local authorization cleared/);

  mode = "reject";
  await store.prepare("candidate-b");
  await store.cancel("candidate-b");
  assert.equal(store.phase, "failed");
  assert.equal(store.prepared, null);
  assert.match(store.error?.message ?? "", /Cancellation status unknown/);
});

test("store: local expiration rejects invalid and past timestamps but permits a future timestamp", async () => {
  const expirationFor = new Map<string, string>([
    ["invalid", "not-a-date"],
    ["past", new Date(Date.now() - 1_000).toISOString()],
    ["future", new Date(Date.now() + 60_000).toISOString()],
  ]);
  const store = setup({
    prepareCandidateConfirmation: async (id) => ({ ...prepared(id), expiresAt: expirationFor.get(id)! }),
    confirmCandidateMemory: async (id) => confirmed(id),
    cancelCandidateConfirmationApproval: async (id) => cancelled(id),
  });

  await store.prepare("invalid");
  assert.equal(store.isPreparedConfirmationExpired, true);
  assert.equal(store.canConfirm, false);
  await store.prepare("past");
  assert.equal(store.isPreparedConfirmationExpired, true);
  await store.prepare("future");
  assert.equal(store.isPreparedConfirmationExpired, false);
  assert.equal(store.canConfirm, true);
});
