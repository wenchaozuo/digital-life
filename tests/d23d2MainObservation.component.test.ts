import fs from "node:fs";
import path from "node:path";

import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BodyRenderer, BodyProvider } from "../src/body";
import type { BodySnapshot, BodyState } from "../src/body/types";
import type { LifeIdentity } from "../src/life";
import type {
  MainScreenObservation,
  MainScreenPerceptionStatus,
} from "../src/perception/screenObservationService";
import type { PersonaTemplate } from "../src/persona";

class Deferred<T> {
  readonly promise: Promise<T>;
  resolve!: (value: T | PromiseLike<T>) => void;

  constructor() {
    this.promise = new Promise<T>((resolve) => {
      this.resolve = resolve;
    });
  }
}

function makeLife(id = "life-a", name = "Life A"): LifeIdentity {
  return {
    id,
    name,
    createdAt: "2026-08-30T00:00:00.000Z",
    version: 1,
    bodyId: "default-png",
    personaId: "persona-1",
    personaVersion: 1,
  };
}

function makePersona(): PersonaTemplate {
  return {
    id: "persona-1",
    name: "Test Persona",
    version: 1,
    coreValues: [],
    personalityTraits: [],
    communicationStyle: {
      tone: "direct",
      preferredExpressions: [],
      avoidedExpressions: [],
    },
    background: "",
    interests: [],
    initiativeLevel: "balanced",
    boundaries: [],
  };
}

function makeObservation(
  text = "D23 MAIN OBSERVE 24680",
  candidateId = "candidate-a",
): MainScreenObservation {
  return {
    capturedAt: "2026-08-30T00:00:00.000Z",
    status: "recognized",
    text,
    truncated: false,
    candidateId,
  };
}

function makeNoTextObservation(): MainScreenObservation {
  return {
    capturedAt: "2026-08-30T00:00:01.000Z",
    status: "noText",
    text: "",
    truncated: false,
    candidateId: "candidate-no-text",
  };
}

const readyStatus: MainScreenPerceptionStatus = {
  consentEnabled: true,
  sessionArmed: true,
  targetSelected: true,
  ready: true,
};

const notReadyStatus: MainScreenPerceptionStatus = {
  consentEnabled: true,
  sessionArmed: false,
  targetSelected: false,
  ready: false,
};

async function flushMicrotasks(rounds = 24): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

async function mountMain(options: {
  life?: LifeIdentity;
  status?: MainScreenPerceptionStatus;
  observation?: MainScreenObservation;
  attachTo?: Element;
} = {}) {
  vi.resetModules();
  const body = await import("../src/body");
  const lifeModule = await import("../src/life");
  const personaModule = await import("../src/persona");
  const storageModule = await import("../src/storage");
  const screenModule = await import("../src/perception/screenObservationService");
  const visionModule = await import("../src/perception/screenVisionDeliveryService");

  const life = options.life ?? makeLife();
  const expressionUnlisten = vi.fn();
  const bindingUnlisten = vi.fn();
  let bindingHandler:
    | ((event: { version: 1; lifeId: string; lifeVersion: number }) => void)
    | undefined;
  let currentSnapshot: BodySnapshot = {
    resourcePath: "idle.png",
    state: "idle",
  };
  const load = async (state: BodyState): Promise<BodySnapshot> => {
    currentSnapshot = { resourcePath: `${state}.png`, state };
    return currentSnapshot;
  };
  const provider: BodyProvider = {
    getCurrent: () => currentSnapshot,
    load,
    switchState: load,
  };
  const renderer: BodyRenderer = {
    mount: vi.fn(),
    render: vi.fn(),
    dispose: vi.fn(),
  };

  vi.spyOn(body.bodyExpressionBridge, "listenForBodyExpression").mockResolvedValue(
    expressionUnlisten,
  );
  vi.spyOn(body.bodyBindingChangedBridge, "listen").mockImplementation(async (handler) => {
    bindingHandler = handler;
    return bindingUnlisten;
  });
  vi.spyOn(body.bodyPackageService, "getRegistrySnapshot").mockResolvedValue([]);
  vi.spyOn(body, "installManagedBodyPackageRegistrySnapshot").mockImplementation(
    () => undefined,
  );
  vi.spyOn(body, "createBodyPresentationForBodyId").mockReturnValue({
    provider,
    renderer,
  });
  vi.spyOn(storageModule.storageService, "initialize").mockResolvedValue();
  vi.spyOn(storageModule.storageService, "getCurrentLife").mockResolvedValue(life);
  vi.spyOn(lifeModule, "initializeDefaultLife").mockResolvedValue(life);
  vi.spyOn(personaModule.personaManager, "getById").mockResolvedValue(makePersona());

  const getStatus = vi
    .spyOn(screenModule.mainScreenObservationService, "getStatus")
    .mockResolvedValue(options.status ?? readyStatus);
  const observeNow = vi
    .spyOn(screenModule.mainScreenObservationService, "observeNow")
    .mockResolvedValue(options.observation ?? makeObservation());
  const prepareMainScreenContextForChat = vi
    .spyOn(screenModule.mainScreenObservationService, "prepareMainScreenContextForChat")
    .mockResolvedValue({ grantId: "grant-opaque" });
  const offerMainScreenContextToChat = vi
    .spyOn(screenModule.mainScreenObservationService, "offerMainScreenContextToChat")
    .mockResolvedValue({ attachmentId: "attachment-opaque" });
  const revokeMainPendingScreenContextGrant = vi
    .spyOn(screenModule.mainScreenObservationService, "revokeMainPendingScreenContextGrant")
    .mockResolvedValue();
  const revokeMainScreenContextAttachment = vi
    .spyOn(screenModule.mainScreenObservationService, "revokeMainScreenContextAttachment")
    .mockResolvedValue();
  const getVisionStatus = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "getStatus")
    .mockResolvedValue({ status: "idle", review: null });
  const prepareVisionReview = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "prepareReview")
    .mockRejectedValue({ code: "VISION_PROVIDER_UNAVAILABLE" });
  const executeVisionReview = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "executeReview")
    .mockRejectedValue({ code: "VISION_REVIEW_UNAVAILABLE" });
  const abandonVisionDelivery = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "abandonDelivery")
    .mockResolvedValue();

  const { default: App } = await import("../src/App.vue");
  const wrapper = mount(App, { attachTo: options.attachTo });
  await flushMicrotasks();

  return {
    wrapper,
    getStatus,
    observeNow,
    prepareMainScreenContextForChat,
    offerMainScreenContextToChat,
    revokeMainPendingScreenContextGrant,
    revokeMainScreenContextAttachment,
    getVisionStatus,
    prepareVisionReview,
    executeVisionReview,
    abandonVisionDelivery,
    emitBindingChange: (event: {
      version: 1;
      lifeId: string;
      lifeVersion: number;
    }) => {
      if (bindingHandler === undefined) {
        throw new Error("binding handler was not registered");
      }
      bindingHandler(event);
    },
    storageService: storageModule.storageService,
    lifeModule,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("D23-D2 Main explicit screen observation", () => {
  it("refreshes readiness on Life-ready mount without invoking observation", async () => {
    const { wrapper, getStatus, observeNow } = await mountMain();
    try {
      expect(getStatus).toHaveBeenCalledWith("life-a");
      expect(observeNow).not.toHaveBeenCalled();
      expect(wrapper.get("[data-testid='screen-perception-indicator']").text()).toContain(
        "Ready",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("refreshes status on window focus without invoking observation", async () => {
    const { wrapper, getStatus, observeNow } = await mountMain();
    try {
      const initialStatusCalls = getStatus.mock.calls.length;
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      expect(getStatus).toHaveBeenCalledTimes(initialStatusCalls + 1);
      expect(getStatus).toHaveBeenLastCalledWith("life-a");
      expect(observeNow).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
    }
  });

  it("invokes exactly one observation for one explicit click", async () => {
    const { wrapper, observeNow } = await mountMain();
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();

      expect(observeNow).toHaveBeenCalledTimes(1);
      expect(observeNow).toHaveBeenCalledWith("life-a");
      expect(wrapper.get("[data-testid='screen-observation-preview']").text()).toContain(
        "D23 MAIN OBSERVE 24680",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("shows an explicit Use in chat action for recognized observations", async () => {
    const { wrapper, prepareMainScreenContextForChat } = await mountMain();
    try {
      expect(wrapper.find("[data-testid='screen-use-in-chat']").exists()).toBe(false);

      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();

      const useInChat = wrapper.get("[data-testid='screen-use-in-chat']");
      expect((useInChat.element as HTMLButtonElement).disabled).toBe(false);
      expect(prepareMainScreenContextForChat).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
    }
  });

  it("shows NoText without enabling Use in chat", async () => {
    const { wrapper, prepareMainScreenContextForChat, offerMainScreenContextToChat } = await mountMain({
      observation: makeNoTextObservation(),
    });
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();

      expect(wrapper.get("[data-testid='screen-observation-no-text']").text()).toContain(
        "No screen text",
      );
      expect(wrapper.find("[data-testid='screen-use-in-chat']").exists()).toBe(false);
      expect(prepareMainScreenContextForChat).not.toHaveBeenCalled();
      expect(offerMainScreenContextToChat).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
    }
  });

  it("completes the handoff in runtime state and disables repeat use", async () => {
    const {
      wrapper,
      observeNow,
      prepareMainScreenContextForChat,
      offerMainScreenContextToChat,
    } = await mountMain();
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();

      expect(prepareMainScreenContextForChat).toHaveBeenCalledTimes(1);
      expect(prepareMainScreenContextForChat).toHaveBeenCalledWith("life-a", "candidate-a");
      expect(offerMainScreenContextToChat).toHaveBeenCalledTimes(1);
      expect(offerMainScreenContextToChat).toHaveBeenCalledWith("life-a", "grant-opaque");
      const useInChat = wrapper.get("[data-testid='screen-use-in-chat']");
      expect((useInChat.element as HTMLButtonElement).disabled).toBe(true);
      expect(useInChat.text()).toBe("Ready in chat");
      expect(wrapper.text()).not.toContain("grant-opaque");
      expect(observeNow).toHaveBeenCalledTimes(1);
    } finally {
      wrapper.unmount();
    }
  });

  it("invalidates a prepared Candidate when a newer observation starts", async () => {
    const first = makeObservation("first observation", "candidate-first");
    const second = makeObservation("second observation", "candidate-second");
    const mounted = await mountMain({ observation: first });
    mounted.observeNow
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second);
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await mounted.wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();
      expect(mounted.wrapper.get("[data-testid='screen-use-in-chat']").text()).toBe(
        "Ready in chat",
      );

      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();

      expect(mounted.wrapper.get("[data-testid='screen-observation-preview']").text()).toContain(
        "second observation",
      );
      expect(mounted.wrapper.get("[data-testid='screen-use-in-chat']").text()).toBe(
        "Use in chat",
      );
      expect(
        (mounted.wrapper.get("[data-testid='screen-use-in-chat']").element as HTMLButtonElement)
          .disabled,
      ).toBe(false);
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("ignores a prepare result that arrives after a newer observation", async () => {
    const first = makeObservation("first observation", "candidate-first");
    const second = makeObservation("second observation", "candidate-second");
    const prepareResult = new Deferred<{ grantId: string }>();
    const mounted = await mountMain({ observation: first });
    mounted.observeNow
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second);
    mounted.prepareMainScreenContextForChat.mockReturnValue(prepareResult.promise);
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await mounted.wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      expect(mounted.prepareMainScreenContextForChat).toHaveBeenCalledTimes(1);

      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      prepareResult.resolve({ grantId: "late-grant" });
      await flushMicrotasks();

      expect(mounted.wrapper.text()).toContain("second observation");
      expect(mounted.wrapper.text()).not.toContain("Ready in chat");
      expect(mounted.wrapper.text()).not.toContain("late-grant");
      expect(mounted.revokeMainPendingScreenContextGrant).toHaveBeenCalledWith(
        "life-a",
        "late-grant",
      );
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("ignores a prepare result that arrives after a Life switch", async () => {
    const lifeB = makeLife("life-b", "Life B");
    const prepareResult = new Deferred<{ grantId: string }>();
    const mounted = await mountMain();
    mounted.prepareMainScreenContextForChat.mockReturnValue(prepareResult.promise);
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await mounted.wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");

      vi.spyOn(mounted.storageService, "getCurrentLife").mockResolvedValue(lifeB);
      mounted.emitBindingChange({ version: 1, lifeId: "life-b", lifeVersion: 2 });
      await flushMicrotasks();
      await vi.waitFor(() => {
        expect(mounted.getStatus).toHaveBeenLastCalledWith("life-b");
      });

      prepareResult.resolve({ grantId: "late-life-grant" });
      await flushMicrotasks();

      expect(mounted.wrapper.text()).not.toContain("late-life-grant");
      expect(mounted.wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(
        false,
      );
      expect(mounted.wrapper.find("[data-testid='screen-use-in-chat']").exists()).toBe(false);
      expect(mounted.revokeMainPendingScreenContextGrant).toHaveBeenCalledWith(
        "life-a",
        "late-life-grant",
      );
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("ignores a prepare result that arrives after Main unmount", async () => {
    const prepareResult = new Deferred<{ grantId: string }>();
    const mounted = await mountMain({ attachTo: document.body });
    mounted.prepareMainScreenContextForChat.mockReturnValue(prepareResult.promise);

    await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
    await flushMicrotasks();
    await mounted.wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
    mounted.wrapper.unmount();

    prepareResult.resolve({ grantId: "late-unmount-grant" });
    await flushMicrotasks();

    expect(document.body.textContent ?? "").not.toContain("late-unmount-grant");
    expect(mounted.revokeMainPendingScreenContextGrant).toHaveBeenCalledWith(
      "life-a",
      "late-unmount-grant",
    );
  });

  it("does not show Ready in chat until the Offer succeeds", async () => {
    const offerResult = new Deferred<{ attachmentId: string }>();
    const mounted = await mountMain();
    mounted.offerMainScreenContextToChat.mockReturnValue(offerResult.promise);
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await mounted.wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();

      expect(mounted.prepareMainScreenContextForChat).toHaveBeenCalledWith(
        "life-a",
        "candidate-a",
      );
      expect(mounted.offerMainScreenContextToChat).toHaveBeenCalledTimes(1);
      expect(mounted.wrapper.get("[data-testid='screen-use-in-chat']").text()).toContain(
        "Transferring",
      );
      expect(mounted.wrapper.text()).not.toContain("Ready in chat");

      offerResult.resolve({ attachmentId: "attachment-opaque" });
      await flushMicrotasks();

      expect(mounted.offerMainScreenContextToChat).toHaveBeenCalledWith(
        "life-a",
        "grant-opaque",
      );
      expect(mounted.wrapper.get("[data-testid='screen-use-in-chat']").text()).toBe(
        "Ready in chat",
      );
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("revokes a late Offer attachment after a newer observation", async () => {
    const first = makeObservation("first observation", "candidate-first");
    const second = makeObservation("second observation", "candidate-second");
    const offerResult = new Deferred<{ attachmentId: string }>();
    const mounted = await mountMain({ observation: first });
    mounted.observeNow
      .mockResolvedValueOnce(first)
      .mockResolvedValueOnce(second);
    mounted.offerMainScreenContextToChat.mockReturnValue(offerResult.promise);
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await mounted.wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();

      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      offerResult.resolve({ attachmentId: "late-attachment" });
      await flushMicrotasks();

      expect(mounted.revokeMainScreenContextAttachment).toHaveBeenCalledWith(
        "late-attachment",
      );
      expect(mounted.wrapper.text()).toContain("second observation");
      expect(mounted.wrapper.text()).not.toContain("Ready in chat");
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("cleans an Offer failure before showing a bounded transfer error", async () => {
    const rawDetail = "C:/private/native-offer-details";
    const mounted = await mountMain();
    mounted.offerMainScreenContextToChat.mockRejectedValue({
      code: "SCREEN_CONTEXT_BROKER_UNAVAILABLE",
      message: rawDetail,
      recoverable: true,
    });
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await mounted.wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();

      expect(mounted.revokeMainPendingScreenContextGrant).toHaveBeenCalledWith(
        "life-a",
        "grant-opaque",
      );
      expect(mounted.wrapper.text()).not.toContain("Ready in chat");
      expect(mounted.wrapper.get("[data-testid='screen-observation-error']").text()).toContain(
        "temporarily unavailable",
      );
      expect(mounted.wrapper.text()).not.toContain(rawDetail);
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("retains a pending grant for bounded cleanup retry when Offer rollback is unavailable", async () => {
    const mounted = await mountMain();
    mounted.offerMainScreenContextToChat.mockRejectedValue({
      code: "SCREEN_CONTEXT_BROKER_UNAVAILABLE",
      message: "offer details must not escape",
      recoverable: true,
    });
    mounted.revokeMainPendingScreenContextGrant.mockRejectedValue({
      code: "SCREEN_CONTEXT_BROKER_UNAVAILABLE",
      message: "cleanup details must not escape",
      recoverable: true,
    });
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await mounted.wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();

      const action = mounted.wrapper.get("[data-testid='screen-use-in-chat']");
      expect(action.text()).toBe("Retry cleanup");
      expect((action.element as HTMLButtonElement).disabled).toBe(false);
      expect(mounted.wrapper.text()).not.toContain("Ready in chat");
      expect(mounted.wrapper.get("[data-testid='screen-observation-error']").text()).toContain(
        "temporarily unavailable",
      );
      expect(mounted.wrapper.text()).not.toContain("offer details must not escape");
      expect(mounted.wrapper.text()).not.toContain("cleanup details must not escape");
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("disables Observe Now while readiness is not valid", async () => {
    const { wrapper, observeNow } = await mountMain({ status: notReadyStatus });
    try {
      const button = wrapper.get("[data-testid='screen-observe-now']");
      expect((button.element as HTMLButtonElement).disabled).toBe(true);
      await button.trigger("click");
      await flushMicrotasks();
      expect(observeNow).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
    }
  });

  it("does not submit a second UI invoke while the first observation is loading", async () => {
    const observation = new Deferred<MainScreenObservation>();
    const { wrapper, observeNow } = await mountMain();
    observeNow.mockReturnValue(observation.promise);
    try {
      const button = wrapper.get("[data-testid='screen-observe-now']");
      await button.trigger("click");
      expect((button.element as HTMLButtonElement).disabled).toBe(true);
      await button.trigger("click");
      expect(observeNow).toHaveBeenCalledTimes(1);

      observation.resolve(makeObservation());
      await flushMicrotasks();
    } finally {
      wrapper.unmount();
    }
  });

  it("renders OCR-looking content as bounded plain text", async () => {
    const text = "<img src=x onerror=alert(1)>";
    const { wrapper } = await mountMain({ observation: makeObservation(text) });
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();

      const preview = wrapper.get("[data-testid='screen-observation-preview']");
      expect(preview.element.textContent).toContain(text);
      expect(wrapper.find("img").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("keeps observation errors bounded and refreshes readiness after failure", async () => {
    const { wrapper, getStatus, observeNow } = await mountMain();
    observeNow.mockRejectedValue({
      code: "SESSION_DENIED",
      message: "C:/private/raw-frame.bin",
      recoverable: false,
    });
    try {
      const initialStatusCalls = getStatus.mock.calls.length;
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();

      expect(observeNow).toHaveBeenCalledTimes(1);
      expect(getStatus).toHaveBeenCalledTimes(initialStatusCalls + 1);
      expect(wrapper.get("[data-testid='screen-observation-error']").text()).toContain(
        "not authorized",
      );
      expect(wrapper.text()).not.toContain("raw-frame.bin");
    } finally {
      wrapper.unmount();
    }
  });

  it("clears the old preview when readiness becomes not ready", async () => {
    const { wrapper, getStatus } = await mountMain();
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(true);

      getStatus.mockResolvedValue(notReadyStatus);
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(false);
      expect(wrapper.get("[data-testid='screen-perception-indicator']").text()).toContain(
        "Disarmed",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("clears preview and handoff when consent becomes disabled", async () => {
    const { wrapper, getStatus } = await mountMain();
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(true);

      getStatus.mockResolvedValue({
        ...readyStatus,
        consentEnabled: false,
        ready: false,
      });
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(false);
      expect(wrapper.find("[data-testid='screen-use-in-chat']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("clears preview and handoff when the session becomes disarmed", async () => {
    const { wrapper, getStatus } = await mountMain();
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(true);

      getStatus.mockResolvedValue({
        ...readyStatus,
        sessionArmed: false,
        ready: false,
      });
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(false);
      expect(wrapper.find("[data-testid='screen-use-in-chat']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("keeps existing prepared handoff when only the capture target is cleared", async () => {
    const { wrapper, getStatus } = await mountMain();
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();

      getStatus.mockResolvedValue({
        ...readyStatus,
        targetSelected: false,
        ready: false,
      });
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      expect(wrapper.get("[data-testid='screen-observation-preview']").text()).toContain(
        "D23 MAIN OBSERVE 24680",
      );
      const useInChat = wrapper.get("[data-testid='screen-use-in-chat']");
      expect((useInChat.element as HTMLButtonElement).disabled).toBe(true);
      expect(useInChat.text()).toBe("Ready in chat");
      expect(
        (wrapper.get("[data-testid='screen-observe-now']").element as HTMLButtonElement).disabled,
      ).toBe(true);
    } finally {
      wrapper.unmount();
    }
  });

  it("clears sensitive presentation state when status authority fails", async () => {
    const { wrapper, getStatus } = await mountMain();
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(true);

      const rawDetail = "C:/private/native-frame-and-grant";
      getStatus.mockRejectedValue({
        code: "UNKNOWN_NATIVE_STATUS_FAILURE",
        message: rawDetail,
        recoverable: false,
      });
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(false);
      expect(wrapper.find("[data-testid='screen-use-in-chat']").exists()).toBe(false);
      expect(wrapper.get("[data-testid='screen-observation-error']").text()).toContain(
        "temporarily unavailable",
      );
      expect(wrapper.text()).not.toContain(rawDetail);
    } finally {
      wrapper.unmount();
    }
  });

  it("maps a bounded prepare failure and clears stale handoff presentation", async () => {
    const { wrapper, prepareMainScreenContextForChat } = await mountMain();
    const rawDetail = "native broker payload with C:/private/grant";
    prepareMainScreenContextForChat.mockRejectedValue({
      code: "SCREEN_CONTEXT_CONSENT_DISABLED",
      message: rawDetail,
      recoverable: false,
    });
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();

      expect(wrapper.find("[data-testid='screen-observation-preview']").exists()).toBe(false);
      expect(wrapper.find("[data-testid='screen-use-in-chat']").exists()).toBe(false);
      expect(wrapper.get("[data-testid='screen-observation-error']").text()).toContain(
        "consent is disabled",
      );
      expect(wrapper.text()).not.toContain(rawDetail);
    } finally {
      wrapper.unmount();
    }
  });

  it("does not render candidate or grant identities", async () => {
    const observation = makeObservation("visible screen text", "candidate-not-rendered");
    const { wrapper, prepareMainScreenContextForChat } = await mountMain({ observation });
    prepareMainScreenContextForChat.mockResolvedValue({ grantId: "grant-not-rendered" });
    try {
      await wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      await wrapper.get("[data-testid='screen-use-in-chat']").trigger("click");
      await flushMicrotasks();

      expect(wrapper.text()).toContain("visible screen text");
      expect(wrapper.text()).not.toContain("candidate-not-rendered");
      expect(wrapper.text()).not.toContain("grant-not-rendered");
    } finally {
      wrapper.unmount();
    }
  });

  it("retires observation presentation ownership when Life changes during observation", async () => {
    const lifeB = makeLife("life-b", "Life B");
    const observation = new Deferred<MainScreenObservation>();
    const mounted = await mountMain();
    mounted.observeNow.mockReturnValue(observation.promise);
    try {
      const button = mounted.wrapper.get("[data-testid='screen-observe-now']");
      await button.trigger("click");
      expect(
        mounted.wrapper.get("[data-testid='screen-perception-indicator']").text(),
      ).toContain("Observing");

      vi.spyOn(mounted.storageService, "getCurrentLife").mockResolvedValue(lifeB);
      mounted.emitBindingChange({ version: 1, lifeId: "life-b", lifeVersion: 2 });
      await flushMicrotasks();
      await vi.waitFor(() => {
        expect(mounted.getStatus).toHaveBeenLastCalledWith("life-b");
      });
      await mounted.wrapper.vm.$nextTick();

      expect(mounted.getStatus).toHaveBeenLastCalledWith("life-b");
      expect(
        mounted.wrapper.get("[data-testid='screen-perception-indicator']").text(),
      ).toContain("Ready");
      expect(
        mounted.wrapper.find("[data-testid='screen-observation-preview']").exists(),
      ).toBe(false);
      expect((button.element as HTMLButtonElement).disabled).toBe(false);

      observation.resolve(makeObservation("Life A late observation"));
      await flushMicrotasks();

      expect(mounted.wrapper.text()).not.toContain("Life A late observation");
      expect(
        mounted.wrapper.find("[data-testid='screen-observation-preview']").exists(),
      ).toBe(false);
      expect(
        mounted.wrapper.get("[data-testid='screen-perception-indicator']").text(),
      ).toContain("Ready");
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("retires a pending observation when accepted readiness becomes not ready", async () => {
    const observation = new Deferred<MainScreenObservation>();
    const mounted = await mountMain();
    mounted.observeNow.mockReturnValue(observation.promise);
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      expect(
        mounted.wrapper.get("[data-testid='screen-perception-indicator']").text(),
      ).toContain("Observing");

      mounted.getStatus.mockResolvedValue(notReadyStatus);
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      expect(
        mounted.wrapper.get("[data-testid='screen-perception-indicator']").text(),
      ).toContain("Disarmed");
      expect(
        mounted.wrapper.find("[data-testid='screen-observation-preview']").exists(),
      ).toBe(false);
      expect(
        (mounted.wrapper.get("[data-testid='screen-observe-now']").element as HTMLButtonElement)
          .disabled,
      ).toBe(true);

      observation.resolve(makeObservation("late after disarm"));
      await flushMicrotasks();

      expect(mounted.wrapper.text()).not.toContain("late after disarm");
      expect(mounted.wrapper.text()).not.toContain("Observing");
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("keeps the bounded status error after readiness lookup fails during observation", async () => {
    const observation = new Deferred<MainScreenObservation>();
    const mounted = await mountMain();
    mounted.observeNow.mockReturnValue(observation.promise);
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");

      mounted.getStatus.mockRejectedValue({
        code: "SESSION_DENIED",
        message: "native detail must not escape",
        recoverable: false,
      });
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      expect(mounted.wrapper.get("[data-testid='screen-observation-error']").text()).toContain(
        "not authorized",
      );
      expect(mounted.wrapper.text()).not.toContain("native detail must not escape");
      expect(
        mounted.wrapper.get("[data-testid='screen-perception-indicator']").text(),
      ).toContain("Needs setup");

      observation.resolve(makeObservation("late after status failure"));
      await flushMicrotasks();

      expect(mounted.wrapper.text()).not.toContain("late after status failure");
      expect(mounted.wrapper.get("[data-testid='screen-observation-error']").text()).toContain(
        "not authorized",
      );
      expect(mounted.wrapper.text()).not.toContain("Observing");
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("prevents an invalidated old request from overwriting a newer request", async () => {
    const oldObservation = new Deferred<MainScreenObservation>();
    const newObservation = new Deferred<MainScreenObservation>();
    const mounted = await mountMain();
    mounted.observeNow
      .mockImplementationOnce(() => oldObservation.promise)
      .mockImplementationOnce(() => newObservation.promise);
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");

      mounted.getStatus.mockResolvedValue(notReadyStatus);
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();

      mounted.getStatus.mockResolvedValue(readyStatus);
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      expect(mounted.observeNow).toHaveBeenCalledTimes(2);

      newObservation.resolve(makeObservation("new request wins"));
      await flushMicrotasks();
      expect(
        mounted.wrapper.get("[data-testid='screen-observation-preview']").text(),
      ).toContain("new request wins");

      oldObservation.resolve(makeObservation("old request must stay hidden"));
      await flushMicrotasks();

      expect(
        mounted.wrapper.get("[data-testid='screen-observation-preview']").text(),
      ).toContain("new request wins");
      expect(mounted.wrapper.text()).not.toContain("old request must stay hidden");
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("clears the old preview and refreshes readiness when Life changes", async () => {
    const lifeB = makeLife("life-b", "Life B");
    const mounted = await mountMain();
    try {
      await mounted.wrapper.get("[data-testid='screen-observe-now']").trigger("click");
      await flushMicrotasks();
      expect(
        mounted.wrapper.find("[data-testid='screen-observation-preview']").exists(),
      ).toBe(true);

      vi.spyOn(mounted.storageService, "getCurrentLife").mockResolvedValue(lifeB);
      mounted.emitBindingChange({ version: 1, lifeId: "life-b", lifeVersion: 2 });
      await flushMicrotasks();
      await mounted.wrapper.vm.$nextTick();

      expect(mounted.getStatus.mock.calls).toContainEqual(["life-b"]);
      expect(
        mounted.wrapper.find("[data-testid='screen-observation-preview']").exists(),
      ).toBe(false);
      expect(mounted.getStatus).toHaveBeenLastCalledWith("life-b");
      expect(mounted.wrapper.text()).toContain("Life B");
    } finally {
      mounted.wrapper.unmount();
    }
  });

  it("keeps the Main D2 command authority out of Settings and Chat ACLs", () => {
    const read = (file: string) =>
      fs.readFileSync(path.join(process.cwd(), file), "utf8");
    const main = read("src-tauri/permissions/main-commands.toml");
    const settings = read("src-tauri/permissions/settings-commands.toml");
    const chat = read("src-tauri/permissions/chat-commands.toml");

    for (const command of ["observe_screen_now", "get_main_screen_perception_status"]) {
      expect(main).toContain(`"${command}"`);
      expect(settings).not.toContain(`"${command}"`);
      expect(chat).not.toContain(`"${command}"`);
    }
  });
});
