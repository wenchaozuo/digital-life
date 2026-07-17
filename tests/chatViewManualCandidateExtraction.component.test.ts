import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";

type TriggerResponse = {
  status: "completed" | "processing" | "retry_wait" | "failed" | "snapshot_invalidated" | "no_eligible_snapshot" | "stale_or_conflict";
  createdCount?: number;
  mergedEvidenceCount?: number;
  blockedCount?: number;
  safeMessageCode: string;
};

const mocks = vi.hoisted(() => ({
  conversationId: "conversation-a" as string | undefined,
  lifeId: "life-a",
  trigger: vi.fn(),
  getCurrent: vi.fn(),
  refreshCandidates: vi.fn(),
  setLifeId: vi.fn(),
  switchConversation: vi.fn(),
}));

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("../src/body", () => ({
  bodyStateMachine: { getState: () => "idle", subscribe: () => () => undefined },
}));
vi.mock("../src/conversation", () => ({
  ConversationError: class ConversationError extends Error {
    code = "CONVERSATION_STORAGE_UNAVAILABLE";
  },
  conversationService: {
    getConversationId: () => mocks.conversationId,
    getConversationTitle: () => "Manual extraction test",
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
    manualCandidateExtractionService: { trigger: mocks.trigger },
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
  lifeIdentityManager: { getCurrent: mocks.getCurrent },
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
    setLifeId = mocks.setLifeId;
    refreshCandidateRecords = mocks.refreshCandidates;
    prepareCandidateById = vi.fn();
    confirmPreparedCandidateById = vi.fn();
    cancelPreparedCandidateById = vi.fn();
    refreshConfirmationData = vi.fn();
  },
}));

import ChatView from "../src/chat/ChatView.vue";

const mountedWrappers: Array<ReturnType<typeof mount>> = [];

function response(status: TriggerResponse["status"], counts: Partial<TriggerResponse> = {}): TriggerResponse {
  return {
    status,
    safeMessageCode: `SAFE_${status.toUpperCase()}`,
    ...counts,
  };
}

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
          template: '<button class="switch-conversation" @click="$emit(\'select\', { id: \'conversation-b\', title: \'B\' })">switch</button>',
        },
      },
    },
  });
  mountedWrappers.push(wrapper);
  return wrapper;
}

function manualButton(wrapper: ReturnType<typeof mount>) {
  return wrapper.findAll(".memory-check-btn")[0];
}

beforeEach(() => {
  mocks.conversationId = "conversation-a";
  mocks.lifeId = "life-a";
  mocks.getCurrent.mockReset().mockImplementation(async () => ({ id: mocks.lifeId }));
  mocks.trigger.mockReset().mockResolvedValue(response("completed", { createdCount: 1, mergedEvidenceCount: 0 }));
  mocks.refreshCandidates.mockReset().mockResolvedValue(undefined);
  mocks.setLifeId.mockReset();
  mocks.switchConversation.mockReset().mockImplementation(async (conversation: { id: string }) => {
    mocks.conversationId = conversation.id;
  });
});

afterEach(() => {
  for (const wrapper of mountedWrappers.splice(0)) wrapper.unmount();
  document.body.innerHTML = "";
});

describe("ChatView manual candidate extraction", () => {
  it("uses the current life and conversation, and disables the action while loading", async () => {
    let resolveTrigger!: (value: TriggerResponse) => void;
    mocks.trigger.mockImplementationOnce(
      () => new Promise<TriggerResponse>((resolve) => { resolveTrigger = resolve; }),
    );
    const wrapper = mountChatView();
    await flushPromises();
    const button = manualButton(wrapper);
    expect(button.exists()).toBe(true);
    expect(button.attributes("disabled")).toBeUndefined();

    await button.trigger("click");
    await wrapper.vm.$nextTick();
    expect(button.attributes("disabled")).toBeDefined();
    await button.trigger("click");
    expect(mocks.trigger).toHaveBeenCalledTimes(1);
    expect(mocks.trigger).toHaveBeenCalledWith("life-a", "conversation-a");

    resolveTrigger(response("completed", { createdCount: 1, mergedEvidenceCount: 0 }));
    await flushPromises();
    expect(button.attributes("disabled")).toBeUndefined();
  });

  it("keeps the action visible but disabled when no current conversation exists", async () => {
    mocks.conversationId = undefined;
    const wrapper = mountChatView();
    await flushPromises();
    expect(manualButton(wrapper).exists()).toBe(true);
    expect(manualButton(wrapper).attributes("disabled")).toBeDefined();
    expect(mocks.trigger).not.toHaveBeenCalled();
  });

  it("keeps completed counts and shows a refresh warning when candidate refresh fails", async () => {
    mocks.trigger.mockResolvedValueOnce(response("completed", { createdCount: 2, mergedEvidenceCount: 1 }));
    mocks.refreshCandidates.mockRejectedValueOnce(new Error("TOKEN_CANARY SQL_CANARY PATH_CANARY CONTENT_CANARY"));
    const wrapper = mountChatView();
    await flushPromises();

    await manualButton(wrapper).trigger("click");
    await flushPromises();

    expect(mocks.refreshCandidates).toHaveBeenCalledTimes(1);
    expect(mocks.setLifeId).toHaveBeenCalledWith("life-a");
    expect(wrapper.text()).toContain("已创建 2 条候选记忆");
    expect(wrapper.text()).toContain("列表刷新失败");
    expect(wrapper.text()).not.toContain("候选记忆提取暂不可用");
    expect(wrapper.text()).not.toContain("TOKEN_CANARY");
    expect(mocks.trigger).toHaveBeenCalledTimes(1);
  });

  it("maps safe completed, failed, and invalidated statuses in the component", async () => {
    for (const status of ["completed", "failed", "snapshot_invalidated"] as const) {
      mocks.trigger.mockResolvedValueOnce(response(status, { createdCount: 0, mergedEvidenceCount: 0 }));
      const wrapper = mountChatView();
      await flushPromises();
      await manualButton(wrapper).trigger("click");
      await flushPromises();
      expect(wrapper.text()).toContain("候选记忆");
      if (status === "completed") expect(wrapper.text()).toContain("没有发现可提取内容");
      expect(wrapper.text()).not.toContain("SAFE_");
      wrapper.unmount();
      mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    }
  });

  it("invalidates an old request when the conversation changes and uses the new conversation ID", async () => {
    let resolveOld!: (value: TriggerResponse) => void;
    mocks.trigger.mockImplementationOnce(
      () => new Promise<TriggerResponse>((resolve) => { resolveOld = resolve; }),
    );
    const wrapper = mountChatView();
    await flushPromises();
    await manualButton(wrapper).trigger("click");
    expect(mocks.trigger).toHaveBeenCalledWith("life-a", "conversation-a");

    await wrapper.find(".switch-conversation").trigger("click");
    await flushPromises();
    resolveOld(response("completed", { createdCount: 9, mergedEvidenceCount: 9 }));
    await flushPromises();
    expect(mocks.refreshCandidates).not.toHaveBeenCalled();
    expect(wrapper.text()).not.toContain("已创建 9 条候选记忆");

    mocks.trigger.mockResolvedValueOnce(response("completed", { createdCount: 1, mergedEvidenceCount: 0 }));
    await manualButton(wrapper).trigger("click");
    await flushPromises();
    expect(mocks.trigger).toHaveBeenLastCalledWith("life-a", "conversation-b");
  });

  it("does not update UI or refresh candidates after unmount, and never renders thrown internals", async () => {
    let resolveTrigger!: (value: TriggerResponse) => void;
    mocks.trigger.mockImplementationOnce(
      () => new Promise<TriggerResponse>((resolve) => { resolveTrigger = resolve; }),
    );
    const wrapper = mountChatView();
    await flushPromises();
    await manualButton(wrapper).trigger("click");
    wrapper.unmount();
    mountedWrappers.splice(mountedWrappers.indexOf(wrapper), 1);
    resolveTrigger(response("completed", { createdCount: 1, mergedEvidenceCount: 0 }));
    await flushPromises();
    expect(mocks.refreshCandidates).not.toHaveBeenCalled();

    mocks.trigger.mockRejectedValueOnce(new Error("TOKEN_CANARY SQL_CANARY PATH_CANARY CONTENT_CANARY"));
    const second = mountChatView();
    await flushPromises();
    await manualButton(second).trigger("click");
    await flushPromises();
    expect(second.text()).not.toContain("TOKEN_CANARY");
    expect(second.text()).not.toContain("SQL_CANARY");
    expect(second.text()).not.toContain("PATH_CANARY");
    expect(second.text()).not.toContain("CONTENT_CANARY");
  });
});
