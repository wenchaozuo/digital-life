import test from "node:test";
import assert from "node:assert/strict";

import {
  CONVERSATION_MEMORY_LIMIT,
  MemoryContextIntegrationError,
  combineConversationSystemContext,
  prepareConversationMemoryContext,
} from "../src/conversation/memoryContextIntegration.ts";
import { ConversationSession } from "../src/conversation/session/conversationSession.ts";

const retrievedMemory = {
  memoryId: "memory-1",
  kind: "preference" as const,
  content: "The user prefers tea.",
  summary: "Prefers tea",
  importance: 0.8,
  confidence: 0.9,
  createdAt: "2026-07-11T00:00:00.000Z",
};

test("retrieval uses life, current input, limit five and appends memory after persona", async () => {
  let capturedQuery: unknown;
  const preparation = await prepareConversationMemoryContext(
    "life-1",
    "What do I prefer?",
    {
      async retrieve(query) {
        capturedQuery = query;
        return [retrievedMemory];
      },
    },
  );

  assert.deepEqual(capturedQuery, {
    lifeId: "life-1",
    queryText: "What do I prefer?",
    limit: CONVERSATION_MEMORY_LIMIT,
  });
  const combined = combineConversationSystemContext(
    "persona-system-context",
    preparation.memoryContext,
  );
  assert.ok(combined.startsWith("persona-system-context\n\n"));
  assert.match(combined, /Prefers tea/);
});

test("database failure degrades to persona-only context with a safe warning", async () => {
  const preparation = await prepareConversationMemoryContext(
    "life-1",
    "hello",
    {
      async retrieve() {
        throw {
          code: "DATABASE_ERROR",
          message: "Storage operation failed.",
          recoverable: true,
        };
      },
    },
  );

  assert.equal(preparation.memoryContext.context, null);
  assert.deepEqual(preparation.warning, {
    code: "MEMORY_RETRIEVAL_UNAVAILABLE",
  });
  assert.equal(
    combineConversationSystemContext("persona", preparation.memoryContext),
    "persona",
  );
});

test("missing life stops memory integration with a structured error", async () => {
  await assert.rejects(
    prepareConversationMemoryContext("missing", "hello", {
      async retrieve() {
        throw {
          code: "LIFE_NOT_FOUND",
          message: "Life not found.",
          recoverable: true,
        };
      },
    }),
    (error: unknown) =>
      error instanceof MemoryContextIntegrationError &&
      error.code === "CONVERSATION_LIFE_NOT_FOUND" &&
      error.recoverable === false,
  );
});

test("retrieved memories are not inserted into ConversationSession", async () => {
  const session = new ConversationSession(
    20,
    "session-1",
    "2026-07-11T00:00:00.000Z",
  );
  session.addMessage({
    role: "user",
    content: "hello",
    timestamp: "2026-07-11T00:00:01.000Z",
  });

  await prepareConversationMemoryContext("life-1", "hello", {
    async retrieve() {
      return [retrievedMemory];
    },
  });

  assert.deepEqual(session.getMessages(), [
    {
      role: "user",
      content: "hello",
      timestamp: "2026-07-11T00:00:01.000Z",
    },
  ]);
});
