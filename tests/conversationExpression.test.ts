import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import {
  ConversationExpressionCoordinator,
  type ConversationExpressionPublisher,
} from "../src/chat/conversationExpression.ts";
import type { BodyState } from "../src/body/types.ts";

function collectingPublisher(): {
  publisher: ConversationExpressionPublisher;
  states: BodyState[];
} {
  const states: BodyState[] = [];
  return {
    states,
    publisher: (state) => {
      states.push(state);
      return Promise.resolve();
    },
  };
}

async function flushMicrotasks(rounds = 32): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

test("mapping: send projects thinking then idle on success", async () => {
  const { publisher, states } = collectingPublisher();
  const coordinator = new ConversationExpressionCoordinator(publisher);

  const token = coordinator.begin("thinking");
  coordinator.complete(token, "idle");
  await flushMicrotasks();

  assert.deepEqual(states, ["thinking", "idle"]);
});

test("mapping: send projects thinking then error on failure", async () => {
  const { publisher, states } = collectingPublisher();
  const coordinator = new ConversationExpressionCoordinator(publisher);

  const token = coordinator.begin("thinking");
  coordinator.complete(token, "error");
  await flushMicrotasks();

  assert.deepEqual(states, ["thinking", "error"]);
});

test("mapping: loading operations project waiting then idle or error", async () => {
  const { publisher, states } = collectingPublisher();
  const coordinator = new ConversationExpressionCoordinator(publisher);

  const restore = coordinator.begin("waiting");
  coordinator.complete(restore, "idle");
  const create = coordinator.begin("waiting");
  coordinator.complete(create, "idle");
  const failed = coordinator.begin("waiting");
  coordinator.complete(failed, "error");
  await flushMicrotasks();

  assert.deepEqual(states, [
    "waiting",
    "idle",
    "waiting",
    "idle",
    "waiting",
    "error",
  ]);
});

test("speaking is never produced by the lifecycle coordinator", async () => {
  const { publisher, states } = collectingPublisher();
  const coordinator = new ConversationExpressionCoordinator(publisher);

  const sendToken = coordinator.begin("thinking");
  coordinator.complete(sendToken, "idle");
  const loadingToken = coordinator.begin("waiting");
  coordinator.complete(loadingToken, "error");
  const recoverToken = coordinator.begin("thinking");
  coordinator.complete(recoverToken, "idle");
  await flushMicrotasks();

  assert.ok(states.length > 0, "a lifecycle must have run");
  for (const state of states) {
    assert.notEqual(state, "speaking", "speaking must never be auto-produced");
  }

  const source = fs.readFileSync(
    new URL("../src/chat/conversationExpression.ts", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(
    source,
    /"speaking"/,
    "the coordinator source must never reference the speaking state literal",
  );
});

test("stale completion from an older operation never overwrites the current one", async () => {
  const { publisher, states } = collectingPublisher();
  const coordinator = new ConversationExpressionCoordinator(publisher);

  // Operation A begins (waiting, token 1), then operation B begins
  // (thinking, token 2).  B completes idle; A completes error late.
  const tokenA = coordinator.begin("waiting");
  const tokenB = coordinator.begin("thinking");
  coordinator.complete(tokenB, "idle");
  coordinator.complete(tokenA, "error");
  await flushMicrotasks();

  assert.deepEqual(states, ["waiting", "thinking", "idle"]);
  assert.ok(!states.includes("error"), "the stale A error must be ignored");
});

test("delivery is serialized even when the first publish is held unresolved", async () => {
  let resolveFirst: (() => void) | undefined;
  const firstSettles = new Promise<void>((resolve) => {
    resolveFirst = resolve;
  });
  const started: BodyState[] = [];
  let call = 0;
  const publisher: ConversationExpressionPublisher = (state) => {
    started.push(state);
    call += 1;
    return call === 1 ? firstSettles : Promise.resolve();
  };
  const coordinator = new ConversationExpressionCoordinator(publisher);

  const token = coordinator.begin("thinking");
  coordinator.complete(token, "idle");
  await flushMicrotasks();

  assert.deepEqual(
    started,
    ["thinking"],
    "the second publish must not start before the first settles",
  );

  resolveFirst?.();
  await firstSettles;
  await flushMicrotasks();

  assert.deepEqual(started, ["thinking", "idle"]);
});

test("a failed publication does not poison the delivery queue", async () => {
  const started: BodyState[] = [];
  let call = 0;
  const publisher: ConversationExpressionPublisher = (state) => {
    started.push(state);
    call += 1;
    return call === 1 ? Promise.reject(new Error("main window unavailable")) : Promise.resolve();
  };
  const coordinator = new ConversationExpressionCoordinator(publisher);

  const sendToken = coordinator.begin("thinking");
  coordinator.complete(sendToken, "idle");
  const nextToken = coordinator.begin("waiting");
  coordinator.complete(nextToken, "idle");
  await flushMicrotasks();

  assert.deepEqual(started, ["thinking", "idle", "waiting", "idle"]);
});

test("publish failure never affects the conversation operation or its result", async () => {
  // A fake publisher that always rejects, like an unavailable main window.
  let publishAttempts = 0;
  const publisher: ConversationExpressionPublisher = () => {
    publishAttempts += 1;
    return Promise.reject(new Error("main window unavailable"));
  };
  const coordinator = new ConversationExpressionCoordinator(publisher);

  let operationExecuted = false;
  async function fakeConversationOperation(): Promise<string> {
    operationExecuted = true;
    return "conversation-ok";
  }

  const token = coordinator.begin("thinking");
  // The core operation does not depend on expression delivery success.
  const result = await fakeConversationOperation();
  coordinator.complete(token, "idle");
  await flushMicrotasks();

  assert.equal(operationExecuted, true);
  assert.equal(result, "conversation-ok");
  assert.equal(publishAttempts, 2, "begin thinking + complete idle");

  // A later legitimate operation still attempts its own publication.
  const nextToken = coordinator.begin("waiting");
  coordinator.complete(nextToken, "idle");
  await flushMicrotasks();
  assert.equal(publishAttempts, 4, "begin waiting + complete idle");
});

test("ChatView production uses the coordinator seam and no false body ownership", () => {
  const chatSource = fs.readFileSync(new URL("../src/chat/ChatView.vue", import.meta.url), "utf8");

  // The conversation expression coordinator is the only body seam.
  assert.match(chatSource, /conversationExpression/);
  assert.match(chatSource, /conversationExpression\.begin\(/);
  assert.match(chatSource, /conversationExpression\.complete\(/);

  // No false chat-side body ownership.
  assert.doesNotMatch(chatSource, /bodyStateMachine/, "ChatView must not own a local machine");
  assert.doesNotMatch(chatSource, /Body state:/, "the stale chat-side display must be gone");

  // No raw Tauri event transport in ChatView.
  assert.doesNotMatch(chatSource, /@tauri-apps\/api\/event/, "no raw Tauri event import");
  assert.doesNotMatch(chatSource, /emitTo\(/, "no raw emitTo calls");
  assert.doesNotMatch(chatSource, /listen\(/, "no raw listen calls");
  assert.doesNotMatch(chatSource, /publishBodyExpression\(/, "no direct bridge calls");

  // No automatic speaking synthesis in ChatView.
  assert.doesNotMatch(chatSource, /speaking/, "ChatView must not auto-publish speaking");
});