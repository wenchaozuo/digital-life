import fs from "node:fs";
import path from "node:path";

import { flushPromises, mount } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

type AttachmentEvent = { payload: unknown };
type AttachmentEventHandler = (event: AttachmentEvent) => void;

const mocks = vi.hoisted(() => ({
  conversationId: "conversation-a" as string | undefined,
  getPending: vi.fn(),
  dismiss: vi.fn(),
  listen: vi.fn(),
  unlisten: vi.fn(),
  eventHandler: undefined as AttachmentEventHandler | undefined,
  switchConversation: vi.fn(),
}));

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
  ConversationError: class ConversationError extends Error {
    code = "CONVERSATION_STORAGE_UNAVAILABLE";
  },
  conversationService: {
    getConversationId: () => mocks.conversationId,
    getConversationTitle: () => "Attachment test conversation",
    getSession: () => ({ getMessages: () => [], subscribe: () => () => undefined }),
    initialize: async () => undefined,
    listConversations: async () => [],
    send: async () => ({ memory: { degradationCodes: [], rebuildRecommended: false } }),
    createConversation: async () => undefined,
    switchConversation: mocks.switchConversation,
    deleteCurrentConversation: async () => undefined,
  },
}));
vi.mock("../src/memory", async () => {
  const actual = await vi.importActual<typeof import("../src/memory")>("../src/memory");
  return {
    ...actual,
    memoryService: {},
    memoryExtractor: {},
    manualCandidateExtractionService: { trigger: vi.fn() },
  };
});
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

function mountChatView() {
  const wrapper = mount(ChatView, {
    attachTo: document.body,
    global: {
      stubs: {
        ChatInput: true,
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

describe("D24-C2 Chat screen-context attachment", () => {
  it("rereads attachment status on mount and on window focus", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    try {
      expect(mocks.getPending).toHaveBeenCalledTimes(1);
      window.dispatchEvent(new Event("focus"));
      await flushPromises();
      expect(mocks.getPending).toHaveBeenCalledTimes(2);
      expect(mocks.dismiss).not.toHaveBeenCalled();
      expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
      mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    }
  });

  it("treats a valid event as a refresh hint and ignores unexpected payloads", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    try {
      expect(mocks.eventHandler).toBeDefined();
      const initialCalls = mocks.getPending.mock.calls.length;

      mocks.eventHandler?.({ payload: { version: 2, attachmentId: "event-only-id" } });
      mocks.eventHandler?.({ payload: { attachmentId: "event-only-id" } });
      await flushPromises();
      expect(mocks.getPending).toHaveBeenCalledTimes(initialCalls);
      expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);

      mocks.getPending.mockResolvedValueOnce({ available: false });
      mocks.eventHandler?.({ payload: { version: 1 } });
      await flushPromises();
      expect(mocks.getPending).toHaveBeenCalledTimes(initialCalls + 1);
      expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
      mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    }
  });

  it("renders only the bounded attachment indicator and never its opaque ID", async () => {
    mocks.getPending.mockResolvedValue({
      available: true,
      attachmentId: "opaque-attachment-123",
    });
    const wrapper = mountChatView();
    await flushPromises();
    try {
      expect(wrapper.get("[data-testid='screen-context-attachment']").text()).toContain(
        "Screen context attached",
      );
      expect(wrapper.text()).toContain("Will be used with your next message");
      expect(wrapper.text()).toContain("Remove");
      expect(wrapper.text()).not.toContain("opaque-attachment-123");
      expect(wrapper.text()).not.toContain("grantId");
      expect(wrapper.text()).not.toContain("candidateId");
      expect(wrapper.text()).not.toContain("capturedAt");
      expect(wrapper.text()).not.toContain("OCR");
    } finally {
      wrapper.unmount();
      mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    }
  });

  it("removes the indicator only after the backend confirms dismissal", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "opaque-attachment" });
    let resolveDismiss!: () => void;
    mocks.dismiss.mockImplementationOnce(
      () => new Promise<void>((resolve) => { resolveDismiss = resolve; }),
    );
    const wrapper = mountChatView();
    await flushPromises();
    try {
      await wrapper.get("[data-testid='screen-context-attachment-remove']").trigger("click");
      expect(mocks.dismiss).toHaveBeenCalledWith("opaque-attachment");
      expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);

      resolveDismiss();
      await flushPromises();
      expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
      mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    }
  });

  it("keeps the indicator and bounds a failed Remove for retry", async () => {
    const rawDetail = "C:/private/native-attachment-details";
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "opaque-attachment" });
    mocks.dismiss.mockRejectedValue({
      code: "SCREEN_CONTEXT_ATTACHMENT_BROKER_UNAVAILABLE",
      message: rawDetail,
      recoverable: true,
    });
    const wrapper = mountChatView();
    await flushPromises();
    try {
      await wrapper.get("[data-testid='screen-context-attachment-remove']").trigger("click");
      await flushPromises();

      expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);
      expect(wrapper.get("[data-testid='screen-context-attachment-error']").text()).toContain(
        "temporarily unavailable",
      );
      expect(wrapper.text()).not.toContain(rawDetail);
      expect(wrapper.get("[data-testid='screen-context-attachment-remove']").attributes("disabled"))
        .toBeUndefined();
    } finally {
      wrapper.unmount();
      mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    }
  });

  it("confirms an already-absent attachment through an authoritative reread", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "old-attachment" });
    mocks.dismiss.mockRejectedValueOnce({
      code: "SCREEN_CONTEXT_ATTACHMENT_NOT_FOUND",
      message: "raw not-found detail",
      recoverable: true,
    });
    const wrapper = mountChatView();
    await flushPromises();
    try {
      mocks.getPending.mockResolvedValueOnce({ available: false });
      await wrapper.get("[data-testid='screen-context-attachment-remove']").trigger("click");
      await flushPromises();

      expect(mocks.getPending).toHaveBeenCalledTimes(2);
      expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(false);
      expect(wrapper.text()).not.toContain("raw not-found detail");
    } finally {
      wrapper.unmount();
      mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    }
  });

  it("does not dismiss when switching conversations", async () => {
    mocks.getPending.mockResolvedValue({ available: true, attachmentId: "next-message-attachment" });
    const wrapper = mountChatView();
    await flushPromises();
    try {
      await wrapper.find(".switch-conversation").trigger("click");
      await flushPromises();

      expect(mocks.switchConversation).toHaveBeenCalledTimes(1);
      expect(mocks.dismiss).not.toHaveBeenCalled();
      expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);
    } finally {
      wrapper.unmount();
      mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    }
  });

  it("does not dismiss on unmount and ignores a late status result", async () => {
    let resolveStatus!: (status: { available: boolean; attachmentId?: string }) => void;
    mocks.getPending.mockImplementationOnce(
      () => new Promise((resolve) => { resolveStatus = resolve; }),
    );
    const wrapper = mountChatView();
    await Promise.resolve();
    wrapper.unmount();
    mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);

    resolveStatus({ available: true, attachmentId: "late-attachment" });
    await flushPromises();

    expect(mocks.dismiss).not.toHaveBeenCalled();
    expect(document.body.textContent ?? "").not.toContain("Screen context attached");
  });

  it("fences an older status reread behind a newer request", async () => {
    let resolveOld!: (status: { available: boolean; attachmentId?: string }) => void;
    mocks.getPending.mockImplementationOnce(
      () => new Promise((resolve) => { resolveOld = resolve; }),
    );
    const wrapper = mountChatView();
    await Promise.resolve();
    mocks.getPending.mockResolvedValueOnce({
      available: true,
      attachmentId: "newer-attachment",
    });
    window.dispatchEvent(new Event("focus"));
    await flushPromises();
    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);

    resolveOld({ available: true, attachmentId: "older-attachment" });
    await flushPromises();
    expect(wrapper.text()).not.toContain("older-attachment");
    expect(wrapper.find("[data-testid='screen-context-attachment']").exists()).toBe(true);

    wrapper.unmount();
    mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
  });

  it("keeps C2 out of conversation requests, persistence, and screen authority", () => {
    const chatView = fs.readFileSync(path.join(process.cwd(), "src/chat/ChatView.vue"), "utf8");
    const attachmentService = fs.readFileSync(
      path.join(process.cwd(), "src/perception/screenContextAttachmentService.ts"),
      "utf8",
    );

    expect(chatView).not.toContain("perceptionAttachmentId");
    expect(chatView).not.toMatch(/observe_screen_now|prepare_main_screen_context_for_chat|offer_main_screen_context_to_chat/);
    expect(chatView).not.toMatch(/localStorage|sessionStorage|indexedDB|console\.(log|info|warn|error)/);
    expect(attachmentService).not.toContain("perceptionAttachmentId");
    expect(attachmentService).not.toMatch(/localStorage|sessionStorage|indexedDB|console\.(log|info|warn|error)/);
    expect(attachmentService).toContain("get_pending_screen_context_attachment");
    expect(attachmentService).toContain("dismiss_pending_screen_context_attachment");
  });
});
