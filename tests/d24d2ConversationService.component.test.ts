import fs from "node:fs";
import path from "node:path";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { ConversationSession } from "../src/conversation/session/conversationSession";
import {
  ConversationService,
  type ConversationServiceDependencies,
} from "../src/conversation/conversationService";
import type { ConversationSummary } from "../src/conversation/conversationHistoryService";
import type {
  ConversationMemoryMetadata,
  GovernedConversationRequest,
  GovernedConversationResponse,
} from "../src/model/modelService";

vi.mock("../src/body", () => ({
  bodyStateMachine: {
    getState: () => "idle",
    transition: vi.fn(),
  },
}));
vi.mock("../src/life", () => ({
  lifeIdentityManager: {
    getCurrent: vi.fn(),
  },
}));
vi.mock("../src/model", () => ({
  modelService: {
    chatWithGovernedContext: vi.fn(),
  },
}));
vi.mock("../src/memory", () => ({
  MemorySourceTypes: { Conversation: "conversation" },
  memoryExtractor: { extract: vi.fn() },
}));
vi.mock("../src/conversation/conversationHistoryService", () => ({
  conversationHistoryService: {
    create: vi.fn(),
    list: vi.fn(),
    getMessages: vi.fn(),
    rename: vi.fn(),
    delete: vi.fn(),
  },
}));

const memory: ConversationMemoryMetadata = {
  retrievedCount: 0,
  usedCount: 0,
  truncated: false,
  degradationCodes: [],
  vectorAvailability: "NO_MEMORY",
  rebuildRecommended: false,
};

function conversation(id: string): ConversationSummary {
  return {
    id,
    title: `Conversation ${id}`,
    createdAt: "2026-08-31T00:00:00.000Z",
    updatedAt: "2026-08-31T00:00:00.000Z",
    lastMessageAt: "2026-08-31T00:00:00.000Z",
  };
}

function response(
  requestId: string,
  conversationId: string,
  replayed = false,
): GovernedConversationResponse {
  return {
    requestId,
    conversationId,
    assistantMessage: "answer",
    persistedMessages: [
      {
        role: "user",
        content: "message",
        sequenceNo: 1,
        createdAt: "2026-08-31T00:00:01.000Z",
      },
      {
        role: "assistant",
        content: "answer",
        sequenceNo: 2,
        createdAt: "2026-08-31T00:00:02.000Z",
      },
    ],
    profileDisplayName: null,
    modelName: null,
    memory,
    latencyMs: 1,
    replayed,
  };
}

function createHarness() {
  const initialConversation = conversation("conversation-a");
  const model = {
    chatWithGovernedContext: vi.fn(),
  };
  const history = {
    create: vi.fn(async () => initialConversation),
    list: vi.fn(async () => []),
    getMessages: vi.fn(async (_conversationId: string) => []),
    rename: vi.fn(async (_conversationId: string, title: string) => ({
      ...initialConversation,
      title,
    })),
    delete: vi.fn(async (conversationId: string) => ({ conversationId, deleted: true })),
  };
  const body = {
    transition: vi.fn(),
    getState: vi.fn(() => "idle"),
  };
  const life = {
    getCurrent: vi.fn(async () => ({ id: "life-a" })),
  };
  const session = new ConversationSession(20, "session-a", "2026-08-31T00:00:00.000Z");
  const dependencies: ConversationServiceDependencies = {
    model,
    life,
    body,
    session,
    history,
  };
  return { service: new ConversationService(dependencies), model, history };
}

function mockSuccess(
  model: ReturnType<typeof createHarness>["model"],
  replayed = false,
): void {
  model.chatWithGovernedContext.mockImplementation(async (request: GovernedConversationRequest) =>
    response(request.requestId, request.conversationId, replayed));
}

function requestsOf(
  model: ReturnType<typeof createHarness>["model"],
): GovernedConversationRequest[] {
  return model.chatWithGovernedContext.mock.calls.map(
    ([request]) => request as GovernedConversationRequest,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("D24-D2 ConversationService perception attachment send", () => {
  it("keeps ordinary sends free of the optional perception field", async () => {
    const { service, model, history } = createHarness();
    mockSuccess(model);

    await service.send({ userInput: "  ordinary message  " });

    expect(history.create).toHaveBeenCalledWith("新对话");
    const [request] = requestsOf(model);
    expect(request).toEqual({
      requestId: expect.any(String),
      conversationId: "conversation-a",
      currentMessage: "ordinary message",
    });
    expect(Object.prototype.hasOwnProperty.call(request, "perceptionAttachmentId")).toBe(false);
  });

  it("sends the exact attachment ID and creates one request ID on the first attached send", async () => {
    const { service, model } = createHarness();
    mockSuccess(model);

    await service.send({ userInput: "  inspect this  ", perceptionAttachmentId: "attachment-a" });

    const [request] = requestsOf(model);
    expect(request).toEqual({
      requestId: expect.any(String),
      conversationId: "conversation-a",
      currentMessage: "inspect this",
      perceptionAttachmentId: "attachment-a",
    });
    expect(model.chatWithGovernedContext).toHaveBeenCalledTimes(1);
  });

  it("reuses the exact request ID and tuple for an unchanged failed attached retry", async () => {
    const { service, model } = createHarness();
    model.chatWithGovernedContext.mockRejectedValueOnce({
      code: "PROVIDER_FAILED",
      message: "provider failed",
      recoverable: true,
    });
    mockSuccess(model);

    await expect(
      service.send({ userInput: "  retry me  ", perceptionAttachmentId: "attachment-a" }),
    ).rejects.toMatchObject({ code: "PROVIDER_FAILED" });
    await service.send({ userInput: "retry me", perceptionAttachmentId: "attachment-a" });

    const requests = requestsOf(model);
    expect(requests[1]).toEqual({
      requestId: requests[0].requestId,
      conversationId: requests[0].conversationId,
      currentMessage: "retry me",
      perceptionAttachmentId: "attachment-a",
    });
  });

  it("rejects a changed message locally while a matching attachment retry is reserved", async () => {
    const { service, model } = createHarness();
    model.chatWithGovernedContext.mockRejectedValueOnce({
      code: "PROVIDER_FAILED",
      message: "provider failed",
      recoverable: true,
    });

    await expect(
      service.send({ userInput: "original", perceptionAttachmentId: "attachment-a" }),
    ).rejects.toMatchObject({ code: "PROVIDER_FAILED" });
    await expect(
      service.send({ userInput: "changed", perceptionAttachmentId: "attachment-a" }),
    ).rejects.toMatchObject({ code: "PERCEPTION_CONTEXT_RETRY_MISMATCH" });
    expect(model.chatWithGovernedContext).toHaveBeenCalledTimes(1);
  });

  it("rejects a changed conversation locally before the model call", async () => {
    const { service, model, history } = createHarness();
    model.chatWithGovernedContext.mockRejectedValueOnce({
      code: "PROVIDER_FAILED",
      message: "provider failed",
      recoverable: true,
    });

    await expect(
      service.send({ userInput: "original", perceptionAttachmentId: "attachment-a" }),
    ).rejects.toMatchObject({ code: "PROVIDER_FAILED" });
    history.getMessages.mockResolvedValueOnce([]);
    await service.switchConversation(conversation("conversation-b"));

    await expect(
      service.send({ userInput: "original", perceptionAttachmentId: "attachment-a" }),
    ).rejects.toMatchObject({ code: "PERCEPTION_CONTEXT_RETRY_MISMATCH" });
    expect(model.chatWithGovernedContext).toHaveBeenCalledTimes(1);
  });

  it("starts a new request ID for a genuinely different attachment", async () => {
    const { service, model } = createHarness();
    model.chatWithGovernedContext.mockRejectedValueOnce({
      code: "PROVIDER_FAILED",
      message: "provider failed",
      recoverable: true,
    });
    mockSuccess(model);

    await expect(
      service.send({ userInput: "same message", perceptionAttachmentId: "attachment-a" }),
    ).rejects.toMatchObject({ code: "PROVIDER_FAILED" });
    await service.send({ userInput: "same message", perceptionAttachmentId: "attachment-b" });

    const requests = requestsOf(model);
    expect(requests[1].perceptionAttachmentId).toBe("attachment-b");
    expect(requests[1].requestId).not.toBe(requests[0].requestId);
  });

  it("clears the matching retry tuple after ordinary governed success", async () => {
    const { service, model } = createHarness();
    mockSuccess(model);

    await service.send({ userInput: "success", perceptionAttachmentId: "attachment-a" });
    await service.send({ userInput: "success", perceptionAttachmentId: "attachment-a" });

    const requests = requestsOf(model);
    expect(requests[1].requestId).not.toBe(requests[0].requestId);
  });

  it("clears the matching retry tuple after replayed success", async () => {
    const { service, model } = createHarness();
    model.chatWithGovernedContext.mockRejectedValueOnce({
      code: "TRANSPORT_OUTCOME_UNKNOWN",
      message: "transport outcome unknown",
      recoverable: true,
    });
    mockSuccess(model, true);

    await expect(
      service.send({ userInput: "replay me", perceptionAttachmentId: "attachment-a" }),
    ).rejects.toMatchObject({ code: "TRANSPORT_OUTCOME_UNKNOWN" });
    await service.send({ userInput: "replay me", perceptionAttachmentId: "attachment-a" });
    mockSuccess(model);
    await service.send({ userInput: "replay me", perceptionAttachmentId: "attachment-a" });

    const requests = requestsOf(model);
    expect(requests[1].requestId).toBe(requests[0].requestId);
    expect(requests[2].requestId).not.toBe(requests[1].requestId);
  });

  it("models a response-lost then replayed-success retry with one stable request ID", async () => {
    const { service, model } = createHarness();
    model.chatWithGovernedContext.mockRejectedValueOnce({
      code: "CONVERSATION_MODEL_FAILED",
      message: "the response was lost after the backend committed",
      recoverable: true,
    });
    mockSuccess(model, true);

    await expect(
      service.send({ userInput: "lost response", perceptionAttachmentId: "attachment-a" }),
    ).rejects.toMatchObject({ code: "CONVERSATION_MODEL_FAILED" });
    const replay = await service.send({
      userInput: "lost response",
      perceptionAttachmentId: "attachment-a",
    });

    const requests = requestsOf(model);
    expect(requests[1].requestId).toBe(requests[0].requestId);
    expect(replay.runtime.replayed).toBe(true);
  });

  it("keeps the retry tuple process-local and exposes only the opaque perception field", () => {
    const read = (relativePath: string) =>
      fs.readFileSync(path.join(process.cwd(), relativePath), "utf8");
    const modelSource = read("src/model/modelService.ts");
    const conversationTypes = read("src/conversation/types.ts");
    const serviceSource = read("src/conversation/conversationService.ts");
    const chatView = read("src/chat/ChatView.vue");
    const governedRequest = modelSource.match(
      /export interface GovernedConversationRequest \{[\s\S]*?\n\}/,
    )?.[0];
    const conversationRequest = conversationTypes.match(
      /export interface ConversationRequest \{[\s\S]*?\n\}/,
    )?.[0];
    const sendStart = serviceSource.indexOf("async send(request: ConversationRequest): Promise<ConversationResponse> {");
    const sendEnd = serviceSource.indexOf("private establishPerceptionRetry", sendStart);
    const sendSource = serviceSource.slice(sendStart, sendEnd);
    const chatSendStart = chatView.indexOf("async function send(content: string): Promise<void> {");
    const chatSendEnd = chatView.indexOf("async function createConversation", chatSendStart);
    const chatSendSource = chatView.slice(chatSendStart, chatSendEnd);

    expect(governedRequest).toContain("perceptionAttachmentId?: string");
    expect(conversationRequest).toContain("perceptionAttachmentId?: string");
    for (const source of [governedRequest, conversationRequest, sendSource, chatSendSource]) {
      expect(source).not.toMatch(/screenText|ocrText|candidateId|grantId/);
    }
    expect(sendSource).not.toMatch(/localStorage|sessionStorage|indexedDB|console\.(log|info|warn|error)/);
    expect(serviceSource).toContain("pendingPerceptionRetry");
    expect(chatSendSource).toContain("perceptionAttachmentId");
  });
});
