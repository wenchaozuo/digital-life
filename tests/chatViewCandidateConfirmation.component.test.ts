import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import {
  CandidateConfirmationError,
  type PreparedCandidateConfirmationPreview,
} from "../src/memory/candidateConfirmationTypes.ts";

const mocks = vi.hoisted(() => {
  const candidateA = {
    id: "ui-a",
    kind: "preference",
    content: "Candidate A",
    summary: "A",
    importance: 0.7,
    confidence: 0.8,
    isSensitive: false,
    sourceType: "conversation",
    sourceCreatedAt: "2026-01-01T00:00:00.000Z",
    sensitiveConsentChecked: false,
    state: "candidateCreated",
    dbRecord: { id: "candidate-a", status: "candidate" },
  };
  const candidateB = {
    ...candidateA,
    id: "ui-b",
    content: "Candidate B",
    summary: "B",
    dbRecord: { id: "candidate-b", status: "candidate" },
  };
  return {
    store: {
      phase: "idle",
      prepared: null as PreparedCandidateConfirmationPreview | null,
      error: null,
      result: null as { candidateId: string; confirmedMemoryId: string; outcome: "confirmed" | "idempotentReplay" } | null,
      clearCandidateConfirmation: vi.fn(),
    },
    prepare: vi.fn(async () => undefined),
    confirm: vi.fn(async () => undefined),
    cancel: vi.fn(async () => undefined),
    refresh: vi.fn(async () => undefined),
    instances: [] as Array<{ candidates: typeof candidateA[] }>,
    candidateA,
    candidateB,
  };
});

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("../src/body", () => ({
  bodyStateMachine: { getState: () => "idle", subscribe: () => () => undefined },
}));
vi.mock("../src/conversation", () => ({
  ConversationError: class ConversationError extends Error {
    code = "CONVERSATION_STORAGE_UNAVAILABLE";
  },
  conversationService: {
    getConversationId: () => "conversation-a",
    getConversationTitle: () => "Test conversation",
    getSession: () => ({ getMessages: () => [], subscribe: () => () => undefined }),
    initialize: async () => undefined,
    listConversations: async () => [],
    send: async () => ({ memory: { degradationCodes: [], rebuildRecommended: false } }),
    createConversation: async () => undefined,
    switchConversation: async () => undefined,
    deleteCurrentConversation: async () => undefined,
  },
}));
vi.mock("../src/memory", () => ({ memoryService: {}, memoryExtractor: {} }));
vi.mock("../src/stores/candidateConfirmation", async () => {
  const { reactive } = await import("vue");
  mocks.store = reactive(mocks.store);
  return { useCandidateConfirmationStore: () => mocks.store };
});
vi.mock("../src/life", () => ({
  lifeIdentityManager: { getCurrent: async () => ({ id: "life-a" }) },
}));
vi.mock("../src/chat/memoryReviewAdapter", () => ({
  createClosePanelHandler: () => () => undefined,
}));
vi.mock("../src/chat/memoryReviewController", () => ({
  MemoryReviewController: class {
    panelState = "reviewing";
    candidates = [mocks.candidateA, mocks.candidateB];
    error = null;
    constructor() {
      mocks.instances.push(this);
    }
    isModified = () => false;
    createCandidate = vi.fn();
    updateCandidate = vi.fn();
    deleteCandidate = vi.fn();
    extract = vi.fn();
    setLifeId = vi.fn();
    prepareCandidateById = mocks.prepare;
    confirmPreparedCandidateById = mocks.confirm;
    cancelPreparedCandidateById = mocks.cancel;
    refreshConfirmationData = mocks.refresh;
  },
}));

import ChatView from "../src/chat/ChatView.vue";
import CandidateConfirmationDialog from "../src/chat/components/CandidateConfirmationDialog.vue";

const mountedWrappers: Array<ReturnType<typeof mount>> = [];

function prepared(candidateId = "candidate-a"): PreparedCandidateConfirmationPreview {
  return {
    candidateId,
    expectedRevision: 1,
    kind: "preference",
    content: "Candidate A",
    summary: "A",
    isSensitive: false,
    source: "conversation",
    confirmationRequirement: "standard",
    expiresAt: "2030-01-01T00:00:00.000Z",
  };
}

function mountChatView() {
  const wrapper = mount(ChatView, {
    attachTo: document.body,
    global: {
      stubs: {
        ChatInput: true,
        ConversationSidebar: true,
        MessageBubble: true,
      },
    },
  });
  mountedWrappers.push(wrapper);
  return wrapper;
}

beforeEach(() => {
  mocks.store.phase = "idle";
  mocks.store.prepared = null;
  mocks.store.error = null;
  mocks.store.result = null;
  mocks.prepare.mockClear();
  mocks.confirm.mockClear();
  mocks.cancel.mockClear();
  mocks.refresh.mockClear();
  mocks.store.clearCandidateConfirmation.mockClear();
  mocks.instances.length = 0;
});

afterEach(() => {
  for (const wrapper of mountedWrappers.splice(0)) wrapper.unmount();
  document.body.innerHTML = "";
});

describe("ChatView candidate confirmation wiring", () => {
  async function enterUncertainCancellation(
    wrapper: ReturnType<typeof mount>,
    message: string,
  ) {
    await wrapper.findAll(".candidate-card .btn-confirm")[0].trigger("click");
    mocks.store.prepared = prepared("candidate-a");
    mocks.store.phase = "prepared";
    await wrapper.vm.$nextTick();
    mocks.cancel.mockImplementationOnce(async () => {
      mocks.store.prepared = null;
      mocks.store.error = new CandidateConfirmationError(
        "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
        message,
        "none",
      );
      mocks.store.phase = "failed";
    });

    const dialog = wrapper.findComponent(CandidateConfirmationDialog);
    await dialog.find(".btn-cancel").trigger("click");
    await flushPromises();
    return dialog;
  }

  it("starts only Prepare from the candidate entry point and blocks a second candidate", async () => {
    const wrapper = mountChatView();
    await flushPromises();

    const buttons = wrapper.findAll(".candidate-card .btn-confirm");
    await buttons[0].trigger("click");

    expect(mocks.prepare).toHaveBeenCalledTimes(1);
    expect(mocks.prepare).toHaveBeenCalledWith("candidate-a");
    expect(mocks.confirm).not.toHaveBeenCalled();
    expect(buttons[1].attributes("disabled")).toBeDefined();
  });

  it("uses the prepared candidate ID after the list order changes for confirm, cancel, and retry", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    await wrapper.findAll(".candidate-card .btn-confirm")[0].trigger("click");

    const controller = mocks.instances[0];
    controller.candidates = [mocks.candidateB, mocks.candidateA];
    mocks.store.prepared = prepared("candidate-a");
    mocks.store.phase = "prepared";
    await wrapper.vm.$nextTick();

    const dialog = wrapper.findComponent(CandidateConfirmationDialog);
    await dialog.find(".btn-confirm").trigger("click");
    expect(mocks.confirm).toHaveBeenCalledWith("candidate-a");

    dialog.vm.$emit("cancel");
    await wrapper.vm.$nextTick();
    expect(mocks.cancel).toHaveBeenCalledWith("candidate-a");

    mocks.store.prepared = null;
    mocks.store.phase = "failed";
    await wrapper.vm.$nextTick();
    dialog.vm.$emit("retryPrepare");
    await wrapper.vm.$nextTick();
    expect(mocks.prepare).toHaveBeenLastCalledWith("candidate-a");
  });

  it("clears only a preparing flow locally and delegates a prepared close to cancellation", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    await wrapper.findAll(".candidate-card .btn-confirm")[0].trigger("click");

    const dialog = wrapper.findComponent(CandidateConfirmationDialog);
    mocks.store.phase = "preparing";
    await wrapper.vm.$nextTick();
    dialog.vm.$emit("close");
    await wrapper.vm.$nextTick();
    expect(mocks.store.clearCandidateConfirmation).toHaveBeenCalledTimes(1);

    mocks.store.prepared = prepared("candidate-a");
    mocks.store.phase = "prepared";
    await wrapper.vm.$nextTick();
    dialog.vm.$emit("cancel");
    await wrapper.vm.$nextTick();
    expect(mocks.cancel).toHaveBeenCalledWith("candidate-a");

    mocks.store.phase = "confirming";
    await wrapper.vm.$nextTick();
    dialog.vm.$emit("close");
    await wrapper.vm.$nextTick();
    expect(mocks.store.clearCandidateConfirmation).toHaveBeenCalledTimes(1);
  });

  it("clears the confirmation flow and refreshes authoritative candidate and confirmed-memory data after success", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    await wrapper.findAll(".candidate-card .btn-confirm")[0].trigger("click");

    mocks.store.result = {
      candidateId: "candidate-a",
      confirmedMemoryId: "memory-a",
      outcome: "idempotentReplay",
    };
    mocks.store.phase = "succeeded";
    await flushPromises();

    expect(mocks.store.clearCandidateConfirmation).toHaveBeenCalledTimes(1);
    expect(mocks.refresh).toHaveBeenCalledTimes(1);
    expect(wrapper.text()).toContain("该记忆此前已经保存。");
  });

  it("reloads authoritative data after cancelled:false without reusing confirmation actions", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    const dialog = await enterUncertainCancellation(
      wrapper,
      "Backend cancellation was not confirmed; local authorization cleared.",
    );

    expect(dialog.find(".uncertain-cancel-banner").exists()).toBe(true);
    expect(wrapper.text()).not.toContain("取消成功");
    await dialog.find(".reload-authoritative-state").trigger("click");
    await flushPromises();

    expect(mocks.cancel).toHaveBeenCalledTimes(1);
    expect(mocks.confirm).not.toHaveBeenCalled();
    expect(mocks.prepare).toHaveBeenCalledTimes(1);
    expect(mocks.refresh).toHaveBeenCalledTimes(1);
    expect(mocks.store.clearCandidateConfirmation).toHaveBeenCalledTimes(1);
    expect(dialog.props("open")).toBe(false);
  });

  it("offers the same authoritative reload after a cancel command exception", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    const dialog = await enterUncertainCancellation(
      wrapper,
      "Cancellation status unknown; local authorization cleared.",
    );

    await dialog.find(".reload-authoritative-state").trigger("click");
    await flushPromises();

    expect(mocks.cancel).toHaveBeenCalledTimes(1);
    expect(mocks.confirm).not.toHaveBeenCalled();
    expect(mocks.prepare).toHaveBeenCalledTimes(1);
    expect(mocks.refresh).toHaveBeenCalledTimes(1);
  });

  it("keeps the uncertain-cancel dialog open when authoritative reload fails and permits a manual retry", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    const dialog = await enterUncertainCancellation(
      wrapper,
      "Cancellation status unknown; local authorization cleared.",
    );
    mocks.refresh.mockRejectedValueOnce(new Error("backend details must not be rendered"));

    await dialog.find(".reload-authoritative-state").trigger("click");
    await flushPromises();

    expect(dialog.props("open")).toBe(true);
    expect(dialog.text()).toContain("重新加载失败，请稍后再试。");
    expect(dialog.text()).not.toContain("backend details must not be rendered");
    expect(dialog.find(".reload-authoritative-state").attributes("disabled")).toBeUndefined();
    expect(mocks.refresh).toHaveBeenCalledTimes(1);

    await dialog.find(".reload-authoritative-state").trigger("click");
    await flushPromises();
    expect(mocks.refresh).toHaveBeenCalledTimes(2);
  });

  it("closes an uncertain cancellation without refreshing authoritative data", async () => {
    const wrapper = mountChatView();
    await flushPromises();
    const dialog = await enterUncertainCancellation(
      wrapper,
      "Backend cancellation was not confirmed; local authorization cleared.",
    );

    await dialog.find(".uncertain-cancel-close").trigger("click");
    await flushPromises();

    expect(mocks.refresh).not.toHaveBeenCalled();
    expect(mocks.store.clearCandidateConfirmation).toHaveBeenCalledTimes(1);
    expect(dialog.props("open")).toBe(false);
    expect(wrapper.text()).not.toContain("取消成功");
  });
});
