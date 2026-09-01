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

const otherReview: MainScreenVisionReview = {
  reviewId: "review-2",
  scope: "FULL_SELECTED_TARGET",
  width: 1280,
  height: 720,
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
  visionResultId: "vision-result-opaque",
};

const idleStatus: MainScreenVisionStatus = { status: "idle", review: null };

async function flushMicrotasks(rounds = 24): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

type MountedMain = Awaited<ReturnType<typeof mountMain>>;

// The main window focus handler rereads the authoritative backend status.
async function refreshViaFocus(): Promise<void> {
  window.dispatchEvent(new Event("focus"));
  await flushMicrotasks();
}

// Drives the D26-F1 required case: Analyze on a reviewReady review, while the
// backend commits and flips to awaitingRetryDecision before the execute error
// refresh rereads it.  The local status stays reviewReady during the click so
// the Analyze button is enabled; the flip applies when the refresh lands.
async function beginRetryFlow(mounted: MountedMain): Promise<void> {
  mounted.setVisionStatus({ status: "reviewReady", review });
  await mounted.wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
  await flushMicrotasks();
  mounted.setVisionStatus({ status: "awaitingRetryDecision", review });
  await mounted.wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
  await flushMicrotasks();
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

  let visionStatus: MainScreenVisionStatus = idleStatus;
  const getVisionStatus = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "getStatus")
    .mockImplementation(async () => visionStatus);
  const prepareVisionReview = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "prepareReview")
    .mockResolvedValue(review);
  const executeVisionReview = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "executeReview")
    .mockResolvedValue(analysis);
  const offerVisionResultToChat = vi
    .spyOn(visionModule.mainScreenVisionDeliveryService, "offerVisionResultToChat")
    .mockResolvedValue({ attachmentId: "vision-attachment-opaque" });
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
      offerVisionResultToChat,
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
    const { wrapper, prepareVisionReview, executeVisionReview, setVisionStatus } =
      await mountMain();
    try {
      setVisionStatus({ status: "reviewReady", review });
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
    const { wrapper, executeVisionReview, setVisionStatus } = await mountMain();
    const deferred = new Deferred<MainScreenVisionAnalysis>();
    executeVisionReview.mockImplementation(async () => deferred.promise);
    try {
      setVisionStatus({ status: "reviewReady", review });
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

  it("exposes explicit Vision use-in-chat only after a result locator exists", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview, offerVisionResultToChat, setVisionStatus } = mounted;
    try {
      setVisionStatus({ status: "reviewReady", review });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();

      const handoff = wrapper.get("[data-testid='screen-vision-use-in-chat']");
      expect(handoff.text()).toContain("Use Vision analysis in chat");
      expect(wrapper.get("[data-testid='screen-vision-result']").text()).toContain(
        "This attaches the AI-generated screen interpretation to your next Chat message.",
      );
      expect(wrapper.get("[data-testid='screen-vision-result']").text()).toContain(
        "The screenshot itself will not be attached.",
      );

      await handoff.trigger("click");
      await flushMicrotasks();
      expect(offerVisionResultToChat).toHaveBeenCalledWith("vision-result-opaque");
      expect(executeVisionReview).toHaveBeenCalledTimes(1);
    } finally {
      wrapper.unmount();
    }
  });

  it("keeps the valid Vision preview while disabling handoff without a result locator", async () => {
    const mounted = await mountMain();
    const { wrapper, offerVisionResultToChat, setVisionStatus } = mounted;
    const unavailableAnalysis: MainScreenVisionAnalysis = {
      ...analysis,
      visionResultId: null,
    };
    mounted.executeVisionReview.mockResolvedValue(unavailableAnalysis);
    try {
      setVisionStatus({ status: "reviewReady", review });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();

      expect(wrapper.get("[data-testid='screen-vision-result']").text()).toContain(
        "A bounded screen summary.",
      );
      const handoff = wrapper.get("[data-testid='screen-vision-use-in-chat']");
      expect(handoff.attributes("disabled")).toBe("");
      await handoff.trigger("click");
      await flushMicrotasks();
      expect(offerVisionResultToChat).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
    }
  });

  it("shows the ambiguous-send warning and retries with the exact same tuple", async () => {
    const { wrapper, executeVisionReview, setVisionStatus } = await mountMain();
    executeVisionReview
      .mockRejectedValueOnce({ code: "VISION_SEND_OUTCOME_UNKNOWN" })
      .mockResolvedValueOnce(analysis);
    try {
      setVisionStatus({ status: "reviewReady", review });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      setVisionStatus({ status: "awaitingRetryDecision", review });
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
    try {
      setVisionStatus({ status: "reviewReady", review });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      setVisionStatus({ status: "awaitingRetryDecision", review });
      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();
      const executeCalls = executeVisionReview.mock.calls.length;

      // The backend abandon completes and returns to idle before the refresh.
      setVisionStatus(idleStatus);
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
    const { wrapper, executeVisionReview, prepareVisionReview, setVisionStatus } =
      await mountMain();
    executeVisionReview.mockRejectedValue({
      code: "VISION_TERMINAL_SETTLEMENT_UNAVAILABLE_AFTER_SEND",
      recoverable: false,
    });
    try {
      setVisionStatus({ status: "reviewReady", review });
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
      // Terminal delivery blocks a new preparation (D26-F2 authority).
      expect(wrapper.get("[data-testid='screen-vision-prepare']").attributes("disabled")).toBe(
        "",
      );

      const prepareCalls = prepareVisionReview.mock.calls.length;
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      expect(prepareVisionReview).toHaveBeenCalledTimes(prepareCalls);
      expect(executeVisionReview).toHaveBeenCalledTimes(1);
    } finally {
      wrapper.unmount();
    }
  });

  it("preserves the exact tuple for a PNG encoding error while awaiting retry", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview } = mounted;
    executeVisionReview.mockRejectedValue({ code: "VISION_PNG_ENCODING_FAILED" });
    try {
      await beginRetryFlow(mounted);
      const [reviewId, confirmationEventId, deliveryId] =
        executeVisionReview.mock.calls[0];
      expect(reviewId).toBe("review-1");
      expect(confirmationEventId).toEqual(expect.any(String));
      expect(deliveryId).toEqual(expect.any(String));
      expect(wrapper.get("[data-testid='screen-vision-error']").text()).toContain(
        "could not be encoded",
      );
      // Backend awaitingRetryDecision + matching attempt: exact tuple retained.
      expect(wrapper.get("[data-testid='screen-vision-analyze']").text()).toContain(
        "Retry this same Vision attempt",
      );
      expect(wrapper.get("[data-testid='screen-vision-abandon']").exists()).toBe(true);
    } finally {
      wrapper.unmount();
    }
  });

  it("preserves the exact tuple for a PNG-too-large error while awaiting retry", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview } = mounted;
    executeVisionReview.mockRejectedValue({ code: "VISION_PNG_TOO_LARGE" });
    try {
      await beginRetryFlow(mounted);
      const [reviewId, confirmationEventId, deliveryId] =
        executeVisionReview.mock.calls[0];
      expect(reviewId).toBe("review-1");
      expect(confirmationEventId).toEqual(expect.any(String));
      expect(deliveryId).toEqual(expect.any(String));
      expect(wrapper.get("[data-testid='screen-vision-error']").text()).toContain(
        "exceeds the allowed size",
      );
      expect(wrapper.get("[data-testid='screen-vision-analyze']").text()).toContain(
        "Retry this same Vision attempt",
      );
      expect(wrapper.get("[data-testid='screen-vision-abandon']").exists()).toBe(true);
    } finally {
      wrapper.unmount();
    }
  });

  it("preserves the exact tuple for a request-too-large error while awaiting retry", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview } = mounted;
    executeVisionReview.mockRejectedValue({ code: "VISION_REQUEST_TOO_LARGE" });
    try {
      await beginRetryFlow(mounted);
      const [reviewId, confirmationEventId, deliveryId] =
        executeVisionReview.mock.calls[0];
      expect(reviewId).toBe("review-1");
      expect(confirmationEventId).toEqual(expect.any(String));
      expect(deliveryId).toEqual(expect.any(String));
      expect(wrapper.get("[data-testid='screen-vision-error']").text()).toContain(
        "exceeds the allowed size",
      );
      expect(wrapper.get("[data-testid='screen-vision-analyze']").text()).toContain(
        "Retry this same Vision attempt",
      );
      expect(wrapper.get("[data-testid='screen-vision-abandon']").exists()).toBe(true);
    } finally {
      wrapper.unmount();
    }
  });

  it("does not clear the tuple for an arbitrary pre-send error while awaiting retry", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview } = mounted;
    executeVisionReview.mockRejectedValue({ code: "VISION_DELIVERY_LEASE_UNAVAILABLE" });
    try {
      await beginRetryFlow(mounted);
      const [reviewId, confirmationEventId, deliveryId] =
        executeVisionReview.mock.calls[0];
      expect(reviewId).toBe("review-1");
      expect(confirmationEventId).toEqual(expect.any(String));
      expect(deliveryId).toEqual(expect.any(String));
      expect(wrapper.get("[data-testid='screen-vision-analyze']").text()).toContain(
        "Retry this same Vision attempt",
      );
      expect(wrapper.get("[data-testid='screen-vision-abandon']").exists()).toBe(true);
    } finally {
      wrapper.unmount();
    }
  });

  it("exact retry reuses the same confirmationEventId", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview } = mounted;
    executeVisionReview
      .mockRejectedValueOnce({ code: "VISION_NOT_SENT" })
      .mockResolvedValueOnce(analysis);
    try {
      await beginRetryFlow(mounted);
      const firstConfirmation = executeVisionReview.mock.calls[0][1];

      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();
      expect(executeVisionReview).toHaveBeenCalledTimes(2);
      expect(executeVisionReview.mock.calls[1][1]).toBe(firstConfirmation);
    } finally {
      wrapper.unmount();
    }
  });

  it("exact retry reuses the same deliveryId", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview } = mounted;
    executeVisionReview
      .mockRejectedValueOnce({ code: "VISION_NOT_SENT" })
      .mockResolvedValueOnce(analysis);
    try {
      await beginRetryFlow(mounted);
      const firstDelivery = executeVisionReview.mock.calls[0][2];

      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();
      expect(executeVisionReview).toHaveBeenCalledTimes(2);
      expect(executeVisionReview.mock.calls[1][2]).toBe(firstDelivery);
    } finally {
      wrapper.unmount();
    }
  });

  it("exact retry remains bound to the same reviewId", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview } = mounted;
    executeVisionReview
      .mockRejectedValueOnce({ code: "VISION_NOT_SENT" })
      .mockResolvedValueOnce(analysis);
    try {
      await beginRetryFlow(mounted);

      await wrapper.get("[data-testid='screen-vision-analyze']").trigger("click");
      await flushMicrotasks();
      expect(executeVisionReview).toHaveBeenCalledTimes(2);
      expect(executeVisionReview.mock.calls[1][0]).toBe("review-1");
    } finally {
      wrapper.unmount();
    }
  });

  it("does not generate new IDs when awaiting retry without an exact tuple", async () => {
    const { wrapper, executeVisionReview, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "awaitingRetryDecision", review });
      await refreshViaFocus();

      const analyze = wrapper.get("[data-testid='screen-vision-analyze']");
      expect(analyze.attributes("disabled")).toBe("");
      expect(analyze.text()).not.toContain("Retry");
      await analyze.trigger("click");
      await flushMicrotasks();
      expect(executeVisionReview).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
    }
  });

  it("allows Abandon when awaiting retry without an exact tuple", async () => {
    const { wrapper, abandonVisionDelivery, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "awaitingRetryDecision", review });
      await refreshViaFocus();

      const abandon = wrapper.get("[data-testid='screen-vision-abandon']");
      expect(abandon.attributes("disabled")).toBeUndefined();
      setVisionStatus(idleStatus);
      await abandon.trigger("click");
      await flushMicrotasks();
      expect(abandonVisionDelivery).toHaveBeenCalledWith("review-1");
      expect(wrapper.find("[data-testid='screen-vision-review']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("backend idle clears a stale local review", async () => {
    const { wrapper, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "reviewReady", review });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.find("[data-testid='screen-vision-review']").exists()).toBe(true);

      setVisionStatus(idleStatus);
      await refreshViaFocus();
      expect(wrapper.find("[data-testid='screen-vision-review']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("backend idle clears a stale local attempt", async () => {
    const mounted = await mountMain();
    const { wrapper, setVisionStatus } = mounted;
    try {
      await beginRetryFlow(mounted);
      expect(executeVisionReviewTuple(mounted)).toBeDefined();

      setVisionStatus(idleStatus);
      await refreshViaFocus();
      expect(wrapper.find("[data-testid='screen-vision-review']").exists()).toBe(false);

      // Re-entering awaiting without the tuple proves the attempt is gone.
      setVisionStatus({ status: "awaitingRetryDecision", review });
      await refreshViaFocus();
      const analyze = wrapper.get("[data-testid='screen-vision-analyze']");
      expect(analyze.attributes("disabled")).toBe("");
    } finally {
      wrapper.unmount();
    }
  });

  it("backend idle removes the Analyze button", async () => {
    const { wrapper, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "reviewReady", review });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.find("[data-testid='screen-vision-analyze']").exists()).toBe(true);

      setVisionStatus(idleStatus);
      await refreshViaFocus();
      expect(wrapper.find("[data-testid='screen-vision-analyze']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("backend review replacement supersedes a stale local review", async () => {
    const { wrapper, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "reviewReady", review });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.get("[data-testid='screen-vision-review']").text()).toContain(
        "vision.example.invalid",
      );

      setVisionStatus({ status: "reviewReady", review: otherReview });
      await refreshViaFocus();
      expect(wrapper.get("[data-testid='screen-vision-review']").text()).toContain(
        "1280 × 720",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("clears an attempt whose review ID mismatches the backend review", async () => {
    const mounted = await mountMain();
    const { wrapper, setVisionStatus } = mounted;
    try {
      await beginRetryFlow(mounted);
      expect(wrapper.get("[data-testid='screen-vision-analyze']").text()).toContain(
        "Retry",
      );

      setVisionStatus({ status: "awaitingRetryDecision", review: otherReview });
      await refreshViaFocus();
      const analyze = wrapper.get("[data-testid='screen-vision-analyze']");
      expect(analyze.attributes("disabled")).toBe("");
      expect(analyze.text()).not.toContain("Retry");
    } finally {
      wrapper.unmount();
    }
  });

  it("display prefers the authoritative backend review", async () => {
    const { wrapper, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "reviewReady", review: otherReview });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      const text = wrapper.get("[data-testid='screen-vision-review']").text();
      expect(text).toContain("1280 × 720");
      expect(text).not.toContain("1920 × 1080");
    } finally {
      wrapper.unmount();
    }
  });

  it("screenVisionCanSend is false for idle", async () => {
    const { wrapper, setVisionStatus } = await mountMain();
    try {
      setVisionStatus(idleStatus);
      await refreshViaFocus();
      expect(wrapper.find("[data-testid='screen-vision-analyze']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("screenVisionCanSend is false for deliveryInProgress", async () => {
    const { wrapper, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "deliveryInProgress", review });
      await refreshViaFocus();
      const analyze = wrapper.find("[data-testid='screen-vision-analyze']");
      expect(analyze.exists()).toBe(true);
      expect(analyze.attributes("disabled")).toBe("");
      expect(wrapper.find("[data-testid='screen-vision-abandon']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("screenVisionCanSend is false for definiteDeliveryObserved", async () => {
    const { wrapper, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "definiteDeliveryObserved", review });
      await refreshViaFocus();
      expect(wrapper.find("[data-testid='screen-vision-analyze']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("screenVisionCanSend is true for reviewReady with the exact review", async () => {
    const { wrapper, executeVisionReview, setVisionStatus } = await mountMain();
    executeVisionReview.mockResolvedValue(analysis);
    try {
      setVisionStatus({ status: "reviewReady", review });
      await wrapper.get("[data-testid='screen-vision-prepare']").trigger("click");
      await flushMicrotasks();
      const analyze = wrapper.get("[data-testid='screen-vision-analyze']");
      expect(analyze.attributes("disabled")).toBeUndefined();
      await analyze.trigger("click");
      await flushMicrotasks();
      expect(executeVisionReview).toHaveBeenCalledTimes(1);
      expect(executeVisionReview.mock.calls[0][0]).toBe("review-1");
    } finally {
      wrapper.unmount();
    }
  });

  it("screenVisionCanSend is true for awaiting only with an exact matching tuple", async () => {
    const mounted = await mountMain();
    const { wrapper, executeVisionReview } = mounted;
    executeVisionReview.mockResolvedValue(analysis);
    try {
      await beginRetryFlow(mounted);
      expect(executeVisionReview).toHaveBeenCalledTimes(1);

      const analyze = wrapper.get("[data-testid='screen-vision-analyze']");
      expect(analyze.attributes("disabled")).toBeUndefined();
      await analyze.trigger("click");
      await flushMicrotasks();
      expect(executeVisionReview).toHaveBeenCalledTimes(2);
      expect(executeVisionReview.mock.calls[1]).toEqual(executeVisionReview.mock.calls[0]);
    } finally {
      wrapper.unmount();
    }
  });

  it("terminal-settlement status never shows retry", async () => {
    const { wrapper, setVisionStatus } = await mountMain();
    try {
      setVisionStatus({ status: "definiteDeliveryObserved", review });
      await refreshViaFocus();
      expect(wrapper.find("[data-testid='screen-vision-analyze']").exists()).toBe(false);
      expect(wrapper.find("[data-testid='screen-vision-abandon']").exists()).toBe(false);
      expect(wrapper.get("[data-testid='screen-vision-review']").text()).toContain(
        "The Vision provider received this image",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("Life-switch stale status cannot reconcile new Life", async () => {
    const { wrapper, getVisionStatus, switchLife } = await mountMain();
    const staleResponse = new Deferred<MainScreenVisionStatus>();
    // The initial mount already consumed the first getStatus call (idle).
    getVisionStatus.mockImplementationOnce(() => staleResponse.promise);
    try {
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();
      switchLife(makeLife("life-b", "Life B"));
      await flushMicrotasks();
      staleResponse.resolve({ status: "awaitingRetryDecision", review });
      await flushMicrotasks();
      expect(wrapper.find("[data-testid='screen-vision-review']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("a stale older status response cannot overwrite latest state", async () => {
    const { wrapper, getVisionStatus, setVisionStatus } = await mountMain();
    const staleResponse = new Deferred<MainScreenVisionStatus>();
    // The initial mount already consumed the first getStatus call (idle).
    getVisionStatus.mockImplementationOnce(() => staleResponse.promise);
    try {
      // Request 1 (stale, in flight) and request 2 (latest) overlap.
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();
      setVisionStatus({ status: "reviewReady", review });
      window.dispatchEvent(new Event("focus"));
      await flushMicrotasks();
      staleResponse.resolve({ status: "awaitingRetryDecision", review });
      await flushMicrotasks();

      const analyze = wrapper.get("[data-testid='screen-vision-analyze']");
      expect(analyze.attributes("disabled")).toBeUndefined();
      expect(analyze.text()).not.toContain("Retry");
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

  function executeVisionReviewTuple(
    mounted: MountedMain,
  ): readonly [string, string, string] | undefined {
    const calls = mounted.executeVisionReview.mock.calls;
    if (calls.length === 0) {
      return undefined;
    }
    const [reviewId, confirmationEventId, deliveryId] = calls[0];
    return [reviewId, confirmationEventId, deliveryId];
  }
});
