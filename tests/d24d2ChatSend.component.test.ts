import { flushPromises, mount } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type AttachmentEvent = { payload: unknown };
type AttachmentEventHandler = (event: AttachmentEvent) => void;

function createDeferred<T>() {
  let resolve!: (value: T | PromiseLike<T>) => void;
  const promise = new Promise<T>((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

const mocks = vi.hoisted(() => {
  class TestConversationError extends Error {
    readonly code: string;
    readonly recoverable: boolean;

    constructor(code: string, message: string, recoverable = true) {
      super(message);
      this.name = "ConversationError";
      this.code = code;
      this.recoverable = recoverable;
    }
  }

  return {
    ConversationError: TestConversationError,
    conversationId: "conversation-a" as string | undefined,
    input: "hello",
    send: vi.fn(),
    getPending: vi.fn(),
    dismiss: vi.fn(),
    listen: vi.fn(),
    unlisten: vi.fn(),
    eventHandler: undefined as AttachmentEventHandler | undefined,
    switchConversation: vi.fn(),
  };
});

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/api/event", () => ({ listen: mocks.listen }));
vi.mock("../src/perception/screenContextAttachmentService", async () => {
  const actual = await vi.importActual<typeof import("../src/perception/screenContextAttachmentService")>(
    "../src/perception/screenContextAttachmentService",
  );
  return {
    ...actual,
    screenContextAttachmentService: {
      getPendingAttachment: mocks.getPending,
      dismissPendingAttachment: mocks.dismiss,
    },
  };
});
vi.mock("../src/conversation", () => ({
  ConversationError: mocks.ConversationError,
  conversationService: {
    getConversationId: () => mocks.conversationId,
    getConversationTitle: () => "D24-D2 conversation",
    getSession: () => ({
      getMessages: () => [],
      subscribe: () => () => undefined,
    }),
    initialize: async () => undefined,
    listConversations: async () => [],
    send: mocks.send,
    createConversation: async () => undefined,
    switchConversation: mocks.switchConversation,
    deleteCurrentConversation: async () => undefined,
  },
}));
vi.mock("../src/memory", () => ({
  extractionStatusMessage: () => undefined,
  manualCandidateExtractionService: { trigger: vi.fn() },
  memoryService: {},
  memoryExtractor: {},
}));
vi.mock("../src/stores/candidateConfirmation", () => ({
  useCandidateConfirmationStore: () => ({
    phase: "idle",
    prepared: null,
    error: null,
    result: null,
    clearCandidateConfirmation: vi.fn(),
  }),
}));
vi.mock("../src/life", () => ({
  lifeIdentityManager: { getCurrent: async () => ({ id: "life-a" }) },
}));
vi.mock("../src/chat/memoryReviewAdapter", () => ({
  createClosePanelHandler: () => () => undefined,
}));
vi.mock("../src/chat/memoryReviewController", () => ({
  MemoryReviewController: class {
    panelState = "empty";
    candidates: unknown[] = [];
    confirmedMemories: unknown[] = [];
    error = null;
    isModified = () => false;
    createCandidate = vi.fn();
    updateCandidate = vi.fn();
    deleteCandidate = vi.fn();
    extract = vi.fn();
    setLifeId = vi.fn();
    refreshCandidateRecords = vi.fn();
    prepareCandidateById = vi.fn();
    confirmPreparedCandidateById = vi.fn();
    cancelPreparedCandidateById = vi.fn();
    refreshConfirmationData = vi.fn();
  },
}));

import ChatView from "../src/chat/ChatView.vue";

const mountedWrappers: Array<ReturnType<typeof mount>> = [];

function successResponse(replayed = false) {
  return {
    replayed,
    memory: { degradationCodes: [], rebuildRecommended: false },
  };
}

function conversationError(
  code: string,
  message = "The conversation request failed.",
): Error {
  return new mocks.ConversationError(code, message);
}

function mountChatView() {
  const chatInputStub = {
    props: {
      disabled: Boolean,
      clearSignal: Number,
    },
    emits: ["send"],
    setup(_: unknown, context: { emit: (event: "send", content: string) => void }) {
      return {
        submit: () => context.emit("send", mocks.input),
      };
    },
    template: '<button data-testid="chat-send" :disabled="disabled" @click="submit">Send</button>',
  };
  const wrapper = mount(ChatView, {
    attachTo: document.body,
    global: {
      stubs: {
        ChatInput: chatInputStub,
        MessageBubble: true,
        CandidateConfirmationDialog: true,
        ConversationSidebar: {
          emits: ["select"],
          template:
            '<button class="switch-conversation" @click="$emit(\'select\', { id: \'conversation-b\', title: \'B\' })">switch</button>',
        },
      },
    },
  });
  mountedWrappers.push(wrapper);
  return wrapper;
}

beforeEach(() => {
  mocks.conversationId = "conversation-a";
  mocks.input = "hello";
  mocks.send.mockReset().mockResolvedValue(successResponse());
  mocks.getPending.mockReset().mockResolvedValue({ available: false });
  mocks.dismiss.mockReset().mockResolvedValue(undefined);
  mocks.listen.mockReset().mockImplementation(
    async (_event: string, handler: AttachmentEventHandler) => {
      mocks.eventHandler = handler;
      return mocks.unlisten;
    },
  );
  mocks.unlisten.mockReset();
  mocks.eventHandler = undefined;
  mocks.switchConversation.mockReset().mockImplementation(async (conversation: { id: string }) => {
    mocks.conversationId = conversation.id;
  });
});

afterEach(() => {
  for (const wrapper of mountedWrappers.splice(0)) wrapper.unmount();
  document.body.innerHTML = "";
});

describe("D24-D2 Chat perception attachment send", () => {
  it("captures the current attachment ID at the user Send boundary", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "attachment-a" });
    const wrapper = mountChatView();
    await flushPromises();

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    await flushPromises();

    expect(mocks.send).toHaveBeenCalledWith({
      userInput: "hello",
      perceptionAttachmentId: "attachment-a",
    });
  });

  it("keeps the attachment indicator and never dismisses after an attached failure", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "attachment-a" });
    mocks.send.mockRejectedValueOnce(conversationError("PROVIDER_FAILED"));
    const wrapper = mountChatView();
    await flushPromises();

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    await flushPromises();

    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);
    expect(mocks.dismiss).not.toHaveBeenCalled();
  });

  it("clears only the captured attachment after success and rereads backend status", async () => {
    mocks.getPending
      .mockReset()
      .mockResolvedValueOnce({ available: true, attachmentId: "attachment-a" })
      .mockResolvedValueOnce({ available: true, attachmentId: "attachment-a" })
      .mockResolvedValueOnce({ available: false });
    const wrapper = mountChatView();
    await flushPromises();

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    await flushPromises();

    expect(mocks.getPending).toHaveBeenCalledTimes(3);
    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);
    expect(mocks.dismiss).not.toHaveBeenCalled();
  });

  it("preserves a newer attachment that arrives while the old send is in flight", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "attachment-old" });
    const pendingResponse = createDeferred<ReturnType<typeof successResponse>>();
    mocks.send.mockReturnValueOnce(pendingResponse.promise);
    const wrapper = mountChatView();
    await flushPromises();

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    await Promise.resolve();
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "attachment-new" });
    mocks.eventHandler?.({ payload: { version: 1 } });
    await flushPromises();
    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);

    pendingResponse.resolve(successResponse());
    await flushPromises();

    expect(mocks.send).toHaveBeenCalledWith({
      userInput: "hello",
      perceptionAttachmentId: "attachment-old",
    });
    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);
  });

  it("keeps a successful send successful when post-success status reread fails", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "attachment-a" });
    const wrapper = mountChatView();
    await flushPromises();
    mocks.getPending.mockRejectedValueOnce(new Error("status transport failed"));

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    await flushPromises();

    expect(mocks.send).toHaveBeenCalledTimes(1);
    expect(wrapper.find(".chat-error").exists()).toBe(false);
    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);
  });

  it("rereads after PERCEPTION_CONTEXT_UNAVAILABLE without retrying as ordinary chat", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "attachment-a" });
    mocks.send.mockRejectedValueOnce(
      conversationError("PERCEPTION_CONTEXT_UNAVAILABLE", "perception unavailable"),
    );
    const wrapper = mountChatView();
    await flushPromises();
    mocks.getPending.mockResolvedValueOnce({ available: false });

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    await flushPromises();

    expect(mocks.send).toHaveBeenCalledTimes(1);
    expect(mocks.send).toHaveBeenCalledWith({
      userInput: "hello",
      perceptionAttachmentId: "attachment-a",
    });
    expect(mocks.getPending).toHaveBeenCalledTimes(3);
    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);
    expect(wrapper.find(".chat-error").text()).toContain("PERCEPTION_CONTEXT_UNAVAILABLE");
  });

  it("keeps an IN_USE attachment visible with bounded retry guidance", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "attachment-a" });
    mocks.dismiss.mockRejectedValueOnce({
      code: "SCREEN_CONTEXT_ATTACHMENT_IN_USE",
      message: "native conversation and request internals",
      recoverable: true,
    });
    const wrapper = mountChatView();
    await flushPromises();

    await wrapper.get("[data-testid='screen-context-attachment-remove']").trigger("click");
    await flushPromises();

    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);
    expect(wrapper.get("[data-testid='screen-context-attachment-error']").text()).toContain(
      "currently reserved for a conversation retry",
    );
    expect(wrapper.text()).not.toContain("native conversation and request internals");
  });

  it("does not consume the attachment when switching conversations", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "attachment-a" });
    mocks.send.mockRejectedValueOnce(conversationError("PROVIDER_FAILED"));
    const wrapper = mountChatView();
    await flushPromises();

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    await flushPromises();
    await wrapper.find(".switch-conversation").trigger("click");
    await flushPromises();

    expect(mocks.switchConversation).toHaveBeenCalledTimes(1);
    expect(mocks.dismiss).not.toHaveBeenCalled();
    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);
  });

  it("keeps ordinary Chat sends free of perception attachment fields", async () => {
    const wrapper = mountChatView();
    await flushPromises();

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    await flushPromises();

    expect(mocks.send).toHaveBeenCalledWith({ userInput: "hello" });
    expect(Object.prototype.hasOwnProperty.call(mocks.send.mock.calls[0][0], "perceptionAttachmentId"))
      .toBe(false);
  });

  it("fences a late old status result so success cannot restore the consumed ID", async () => {
    const oldStatus = createDeferred<{ available: boolean; attachmentId?: string }>();
    mocks.getPending
      .mockReset()
      .mockImplementationOnce(() => oldStatus.promise)
      .mockResolvedValue({ available: true, attachmentId: "attachment-old" });
    const wrapper = mountChatView();
    await Promise.resolve();
    await flushPromises();
    const pendingResponse = createDeferred<ReturnType<typeof successResponse>>();
    mocks.send.mockReturnValueOnce(pendingResponse.promise);

    await wrapper.get("[data-testid='chat-send']").trigger("click");
    oldStatus.resolve({ available: true, attachmentId: "attachment-old" });
    await flushPromises();
    pendingResponse.resolve(successResponse(true));
    await flushPromises();

    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);
  });
});
