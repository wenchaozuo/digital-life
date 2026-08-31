import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BodyRenderer, BodyProvider } from "../src/body";
import type { BodySnapshot, BodyState } from "../src/body/types";
import type { LifeIdentity } from "../src/life";
import type {
  MainScreenObservation,
  MainScreenPerceptionStatus,
} from "../src/perception/screenObservationService";
import type {
  MainScreenVisionAnalysis,
  MainScreenVisionReview,
  MainScreenVisionStatus,
} from "../src/perception/screenVisionDeliveryService";
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
    createdAt: "2026-08-31T00:00:00.000Z",
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

const readyStatus: MainScreenPerceptionStatus = {
  consentEnabled: true,
  sessionArmed: true,
  targetSelected: true,
  ready: true,
};

const review: MainScreenVisionReview = {
  reviewId: "review-1",
  scope: "FULL_SELECTED_TARGET",
  width: 1920,
  height: 1080,
  providerKind: "openai_compatible",
  providerHost: "vision.example.invalid",
  profileDisplayName: "Work Vision",
  modelName: "vision-model",
};

const analysis: MainScreenVisionAnalysis = {
  summary: "A bounded screen summary.",
  observations: ["A visible application window."],
  providerDisplayName: "Work Vision",
  modelName: "vision-model",
};

async function flushMicrotasks(rounds = 24): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

async function mountMain() {
  vi.resetModules();
  const body = await import("../src/body");
  const lifeModule = await import("../src/life");
  const personaModule = await import("../src/persona");
  const storageModule = await import("../src/storage");
  const screenModule = await import("../src/perception/screenObservationService");
  const visionModule = await import("../src/perception/screenVisionDeliveryService");

  const life = makeLife();
  const expressionUnlisten = vi.fn();
  const bindingUnlisten = vi.fn();
  let bindingHandler:
    | ((event: { version: 1; lifeId: string; lifeVersion: number }) => void)
    | undefined;
  let currentSnapshot: BodySnapshot = { resourcePath: "idle.png", state: "idle" };
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
  vi.spyOn(body, "createBodyPresentationForBodyId").mockReturnValue({ provider, renderer });
  vi.spyOn(storageModule.storageService, "initialize").mockResolvedValue();
  const getCurrentLife = vi
    .spyOn(storageModule.storageService, "getCurrentLife")
    .mockResolvedValue(life);
  vi.spyOn(lifeModule, "initializeDefaultLife").mockResolvedValue(life);
  vi.spyOn(personaModule.personaManager, "getById").mockResolvedValue(makePersona());

  vi.spyOn(screenModule.mainScreenObservationService, "getStatus").mockResolvedValue(
    readyStatus,
  );
  vi.spyOn(screenModule.mainScreenObservationService, "observeNow").mockResolvedValue({
    capturedAt: "2026-08-31T00:00:00.000Z",
    status: "recognized",
    text: "",
    truncated: false,
    candidateId: "candidate-a",
  } satisfies MainScreenObservation);
  vi.spyOn(
    screenModule.mainScreenObservationService,
    "prepareMainScreenContextForChat",
  ).mockResolvedValue({ grantId: "grant-opaque" });
  vi.spyOn(
    screenModule.mainScreenObservationService,
    "offerMainScreenContextToChat",
  ).mockResolvedValue({ attachmentId: "attachment-opaque" });
  vi.spyOn(
    screenModule.mainScreenObservationService,
    "revokeMainPendingScreenContextGrant",
  ).mockResolvedValue();
  vi.spyOn(
    screenModule.mainScreenObservationService,
    "revokeMainScreenContextAttachment",
  ).mockResolvedValue();

  let visionStatus: MainScreenVisionStatus = { status: "idle", review: null };
  const getVisionStatus = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "getStatus")
    .mockImplementation(async () => visionStatus);
  const prepareVisionReview = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "prepareReview")
    .mockResolvedValue(review);
  const executeVisionReview = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "executeReview")
    .mockResolvedValue(analysis);
  const abandonVisionDelivery = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "abandonDelivery")
    .mockResolvedValue();

  const { default: App } = await import("../src/App.vue");
  const wrapper = mount(App);
  await flushMicrotasks();

  return {
    wrapper,
    getVisionStatus,
    prepareVisionReview,
    executeVisionReview,
    abandonVisionDelivery,
    setVisionStatus: (status: MainScreenVisionStatus) => {
      visionStatus = status;
    },
    switchLife: (nextLife: LifeIdentity) => {
      getCurrentLife.mockResolvedValue(nextLife);
      if (bindingHandler === undefined) {
        throw new Error("binding handler was not registered");
      }
      bindingHandler({ version: 1, lifeId: nextLife.id, lifeVersion: nextLife.version });
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("D26-B Main explicit governed Vision delivery", () => {
  it("prepares a safe review and never sends during preparation", async () => {
    const { wrapper, prepareVisionReview, executeVisionReview } = await mountMain();
    try {
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();

      expect(prepareVisionReview).toHaveBeenCalledTimes(1);
      expect(prepareVisionReview.mock.calls[0]).toHaveLength(0);
      expect(executeVisionReview).not.toHaveBeenCalled();
      const text = wrapper.get("[data-testid='screen-vision-review']").text();
      expect(text).toContain("vision.example.invalid");
      expect(text).toContain("vision-model");
      expect(text).toContain("The image has not been sent yet.");
      expect(text).toContain("No additional manual privacy masks are applied");
    } finally {
      wrapper.unmount();
    }
  });

  it("sends only after an explicit click and fences a double click to one attempt", async () => {
    const { wrapper, executeVisionReview } = await mountMain();
    const deferred = new Deferred<MainScreenVisionAnalysis>();
    executeVisionReview.mockImplementation(
      async () => deferred.promise,
    );
    try {
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      const analyze = wrapper.get("[data-testid='screen-vision-analyze']");
      await analyze.trigger("click");
      await analyze.trigger("click");

      expect(executeVisionReview).toHaveBeenCalledTimes(1);
      const [reviewId, confirmationEventId, deliveryId] =
        executeVisionReview.mock.calls[0];
      expect(reviewId).toBe("review-1");
      expect(confirmationEventId).toEqual(expect.any(String));
      expect(deliveryId).toEqual(expect.any(String));
      expect(confirmationEventId).not.toBe(deliveryId);

      deferred.resolve(analysis);
      await flushMicrotasks();
      expect(wrapper.get("[data-testid='screen-vision-result']").text()).toContain(
        "A bounded screen summary.",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("shows the ambiguous-send warning and retries with the exact same tuple", async () => {
    const { wrapper, executeVisionReview, setVisionStatus } = await mountMain();
    executeVisionReview
      .mockRejectedValueOnce({ code: "VISION_SEND_OUTCOME_UNKNOWN" })
      .mockResolvedValueOnce(analysis);
    setVisionStatus({ status: "awaitingRetryDecision", review });
    try {
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();

      expect(wrapper.get("[data-testid='screen-vision-error']").text()).toContain(
        "may have been sent",
      );
      const firstAttempt = executeVisionReview.mock.calls[0];
      expect(wrapper.get("[data-testid='screen-vision-analyze']").text()).toContain(
        "Retry this same Vision attempt",
      );

      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();
      expect(executeVisionReview).toHaveBeenCalledTimes(2);
      expect(executeVisionReview.mock.calls[1]).toEqual(firstAttempt);
      expect(wrapper.get("[data-testid='screen-vision-result']").text()).toContain(
        "A bounded screen summary.",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("abandons a retained attempt without creating IDs or sending again", async () => {
    const { wrapper, executeVisionReview, abandonVisionDelivery, setVisionStatus } =
      await mountMain();
    executeVisionReview.mockRejectedValue({ code: "VISION_NOT_SENT" });
    setVisionStatus({ status: "awaitingRetryDecision", review });
    try {
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();
      const executeCalls = executeVisionReview.mock.calls.length;

      setVisionStatus({ status: "idle", review: null });
      await wrapper.get("[data-testid='screen-vision-abandon']").trigger("click");
      await flushMicrotasks();
      expect(abandonVisionDelivery).toHaveBeenCalledWith("review-1");
      expect(executeVisionReview).toHaveBeenCalledTimes(executeCalls);
      expect(wrapper.find("[data-testid='screen-vision-review']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("shows a definite-delivery terminal error without retry or another send", async () => {
    const { wrapper, executeVisionReview, setVisionStatus } = await mountMain();
    executeVisionReview.mockRejectedValue({
      code: "VISION_TERMINAL_SETTLEMENT_UNAVAILABLE_AFTER_SEND",
      recoverable: false,
    });
    try {
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      setVisionStatus({ status: "definiteDeliveryObserved", review });
      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();

      const section = wrapper.get("[data-testid='main-screen-vision-delivery']");
      expect(executeVisionReview).toHaveBeenCalledTimes(1);
      expect(section.text()).toContain(
        "The Vision provider received this image, but local one-shot finalization could not be completed.",
      );
      expect(section.text()).not.toContain("The image has not been sent yet.");
      expect(section.text()).not.toContain("Retry");
      expect(section.find("[data-testid='screen-vision-analyze']").exists()).toBe(false);
      expect(section.find("[data-testid='screen-vision-abandon']").exists()).toBe(false);
      expect(wrapper.get("[data-testid='screen-vision-prepare']").attributes("disabled")).toBe(
        "",
      );

      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      expect(executeVisionReview).toHaveBeenCalledTimes(1);
    } finally {
      wrapper.unmount();
    }
  });

  it("drops a stale preparation result after the current Life changes", async () => {
    const { wrapper, prepareVisionReview, switchLife } = await mountMain();
    const deferred = new Deferred<MainScreenVisionReview>();
    prepareVisionReview.mockImplementation(async () => deferred.promise);
    try {
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      switchLife(makeLife("life-b", "Life B"));
      await flushMicrotasks();
      deferred.resolve(review);
      await flushMicrotasks();

      expect(wrapper.find("[data-testid='screen-vision-review']").exists()).toBe(false);
      expect(wrapper.html()).not.toContain("base64");
    } finally {
      wrapper.unmount();
    }
  });
});
