import fs from "node:fs";
import path from "node:path";

import { mount } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { invoke } from "@tauri-apps/api/core";
import type { LifeIdentity } from "../src/life";
import ScreenPerceptionSettingsView from "../src/settings/perception/ScreenPerceptionSettingsView.vue";
import {
  screenPerceptionSettingsService,
  type ScreenPerceptionPolicy,
  type ScreenPerceptionSessionStatus,
} from "../src/settings/perception/screenPerceptionSettingsService";
import {
  screenVisionOutboundErrorFromUnknown,
  screenVisionOutboundSettingsService,
  type ScreenVisionOutboundPolicy,
} from "../src/settings/perception/screenVisionOutboundSettingsService";
import { screenCaptureSettingsService } from "../src/settings/perception/screenCaptureService";
import { storageService } from "../src/storage";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const mockedInvoke = vi.mocked(invoke);

function makeLife(id = "life-a", name = "Life A"): LifeIdentity {
  return {
    id,
    name,
    createdAt: "2026-08-31T00:00:00.000Z",
    version: 1,
    bodyId: "default-body",
    personaId: "persona-1",
    personaVersion: 1,
  };
}

function makeLocalPolicy(
  lifeId = "life-a",
  enabled = false,
  revision = 1,
): ScreenPerceptionPolicy {
  return {
    lifeId,
    enabled,
    revision,
    createdAt: "2026-08-31T00:00:00.000Z",
    updatedAt: "2026-08-31T00:00:00.000Z",
  };
}

function makeOutboundPolicy(
  lifeId = "life-a",
  enabled = false,
  revision = 1,
): ScreenVisionOutboundPolicy {
  return {
    lifeId,
    enabled,
    revision,
    createdAt: "2026-08-31T00:00:00.000Z",
    updatedAt: "2026-08-31T00:00:00.000Z",
  };
}

async function flushMicrotasks(rounds = 16): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

function deferred<T>(): {
  promise: Promise<T>;
  resolve: (value: T) => void;
  reject: (reason?: unknown) => void;
} {
  let resolvePromise: (value: T) => void = () => undefined;
  let rejectPromise: (reason?: unknown) => void = () => undefined;
  const promise = new Promise<T>((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  return { promise, resolve: resolvePromise, reject: rejectPromise };
}

async function mountSettings(options: {
  life?: LifeIdentity;
  localPolicy?: ScreenPerceptionPolicy | null;
  session?: ScreenPerceptionSessionStatus;
  outboundPolicy?: ScreenVisionOutboundPolicy | null;
} = {}) {
  vi.spyOn(storageService, "getCurrentLife").mockResolvedValue(
    options.life ?? makeLife(),
  );
  vi.spyOn(screenPerceptionSettingsService, "getPolicy").mockResolvedValue(
    options.localPolicy === undefined
      ? makeLocalPolicy("life-a", true)
      : options.localPolicy,
  );
  vi.spyOn(screenPerceptionSettingsService, "getSessionStatus").mockResolvedValue(
    options.session ?? { status: "disarmed" },
  );
  vi.spyOn(screenCaptureSettingsService, "getTargetStatus").mockResolvedValue({
    status: "none",
  });
  const getOutboundPolicy = vi
    .spyOn(screenVisionOutboundSettingsService, "getPolicy")
    .mockResolvedValue(
      options.outboundPolicy === undefined ? null : options.outboundPolicy,
    );

  const wrapper = mount(ScreenPerceptionSettingsView);
  await flushMicrotasks();
  return { wrapper, getOutboundPolicy };
}

afterEach(() => {
  vi.restoreAllMocks();
});

beforeEach(() => {
  mockedInvoke.mockReset();
});

describe("D25-B2 outbound Settings service", () => {
  it("uses the exact frozen B1 get command and request", async () => {
    mockedInvoke.mockResolvedValue(null);

    await screenVisionOutboundSettingsService.getPolicy("life-a");

    expect(mockedInvoke).toHaveBeenCalledWith(
      "get_screen_vision_outbound_policy",
      { request: { lifeId: "life-a" } },
    );
  });

  it("creates only a disabled policy with lifeId", async () => {
    mockedInvoke.mockResolvedValue(makeOutboundPolicy());

    await screenVisionOutboundSettingsService.createPolicy("life-a");

    expect(mockedInvoke).toHaveBeenCalledWith(
      "create_screen_vision_outbound_policy",
      { request: { lifeId: "life-a" } },
    );
    const createArguments = mockedInvoke.mock.calls[0]?.[1] as {
      request: Record<string, unknown>;
    };
    expect(createArguments.request).not.toHaveProperty("enabled");
  });

  it("updates with a secure event id and no actorKind", async () => {
    mockedInvoke.mockResolvedValue(makeOutboundPolicy("life-a", true, 2));

    await screenVisionOutboundSettingsService.updatePolicy("life-a", true, 1);

    const [command, argumentsValue] = mockedInvoke.mock.calls[0] as [
      string,
      { request: Record<string, unknown> },
    ];
    expect(command).toBe("update_screen_vision_outbound_policy");
    expect(argumentsValue.request).toMatchObject({
      lifeId: "life-a",
      enabled: true,
      expectedRevision: 1,
    });
    expect(argumentsValue.request.eventId).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
    expect(argumentsValue.request).not.toHaveProperty("actorKind");
  });

  it("maps only bounded backend codes and never reflects raw text", () => {
    const mapped = screenVisionOutboundErrorFromUnknown({
      code: "SCREEN_VISION_OUTBOUND_REVISION_CONFLICT",
      message: "C:/private/secret.sqlite3 and event-id-raw",
      recoverable: false,
    });
    expect(mapped.message).not.toContain("secret.sqlite3");
    expect(mapped.message).not.toContain("event-id-raw");
    expect(mapped.recoverable).toBe(false);

    const unknown = screenVisionOutboundErrorFromUnknown({
      code: "UNEXPECTED_BACKEND_FAILURE",
      message: "private backend details",
    });
    expect(unknown.code).toBe("SCREEN_VISION_OUTBOUND_SETTINGS_UNAVAILABLE");
    expect(unknown.message).not.toContain("private backend details");
  });

  it("has no persistence or image/network transport dependency", () => {
    const source = fs.readFileSync(
      path.join(process.cwd(), "src/settings/perception/screenVisionOutboundSettingsService.ts"),
      "utf8",
    );
    expect(source).not.toMatch(/localStorage|sessionStorage|indexedDB/i);
    expect(source).not.toMatch(/fetch\(|FormData|base64|multipart|Vision API|screenshot|ocr/i);
  });
});

describe("D25-B2 outbound Settings UX", () => {
  it("renders a missing policy as disabled and does not create on mount", async () => {
    const { wrapper, getOutboundPolicy } = await mountSettings({
      outboundPolicy: null,
    });
    const createPolicy = vi.spyOn(
      screenVisionOutboundSettingsService,
      "createPolicy",
    );
    try {
      expect(wrapper.get("[data-testid='screen-vision-outbound-status']").text()).toBe(
        "Disabled",
      );
      expect(wrapper.get("[data-testid='screen-vision-outbound-no-policy']").text()).toContain(
        "No screen-image sharing permission has been granted for this Life.",
      );
      expect(getOutboundPolicy).toHaveBeenCalledWith("life-a");
      expect(createPolicy).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
    }
  });

  it("performs first enable as create-disabled then update-true with returned revision", async () => {
    const created = makeOutboundPolicy("life-a", false, 7);
    const enabled = makeOutboundPolicy("life-a", true, 8);
    const { wrapper } = await mountSettings({ outboundPolicy: null });
    const createPolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "createPolicy")
      .mockResolvedValue(created);
    const updatePolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "updatePolicy")
      .mockResolvedValue(enabled);
    const armSession = vi.spyOn(screenPerceptionSettingsService, "armSession");
    try {
      await wrapper.get("[data-testid='screen-vision-outbound-enable']").trigger("click");
      await flushMicrotasks();

      expect(createPolicy).toHaveBeenCalledWith("life-a");
      expect(updatePolicy).toHaveBeenCalledWith("life-a", true, 7);
      expect(armSession).not.toHaveBeenCalled();
      expect(wrapper.get("[data-testid='screen-vision-outbound-status']").text()).toBe(
        "Enabled",
      );
      expect(wrapper.get("[data-testid='screen-vision-outbound-revision']").text()).toBe(
        "8",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("keeps first-enable creation durable when the follow-up update fails", async () => {
    const created = makeOutboundPolicy("life-a", false, 7);
    const { wrapper, getOutboundPolicy } = await mountSettings({
      outboundPolicy: null,
    });
    getOutboundPolicy.mockResolvedValueOnce(created);
    const createPolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "createPolicy")
      .mockResolvedValue(created);
    const updatePolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "updatePolicy")
      .mockRejectedValue({
        code: "SCREEN_VISION_OUTBOUND_DATABASE_UNAVAILABLE",
        message: "raw database details",
      });
    try {
      await wrapper.get("[data-testid='screen-vision-outbound-enable']").trigger("click");
      await flushMicrotasks();

      expect(createPolicy).toHaveBeenCalledTimes(1);
      expect(updatePolicy).toHaveBeenCalledTimes(1);
      expect(getOutboundPolicy).toHaveBeenCalledTimes(2);
      expect(wrapper.get("[data-testid='screen-vision-outbound-status']").text()).toBe(
        "Disabled",
      );
      expect(wrapper.find("[data-testid='screen-vision-outbound-no-policy']").exists()).toBe(
        false,
      );
      expect(wrapper.get("[data-testid='screen-vision-outbound-error']").text()).not.toContain(
        "raw database details",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("disables outbound consent without changing local D23 consent or session", async () => {
    const { wrapper } = await mountSettings({
      localPolicy: makeLocalPolicy("life-a", true, 3),
      session: { status: "armed", lifeId: "life-a" },
      outboundPolicy: makeOutboundPolicy("life-a", true, 4),
    });
    const updatePolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "updatePolicy")
      .mockResolvedValue(makeOutboundPolicy("life-a", false, 5));
    const disarmSession = vi.spyOn(screenPerceptionSettingsService, "disarmSession");
    try {
      await wrapper.get("[data-testid='screen-vision-outbound-disable']").trigger("click");
      await flushMicrotasks();

      expect(updatePolicy).toHaveBeenCalledWith("life-a", false, 4);
      expect(disarmSession).not.toHaveBeenCalled();
      expect(wrapper.get("[data-testid='screen-vision-outbound-status']").text()).toBe(
        "Disabled",
      );
      expect(wrapper.get("[data-testid='screen-perception-consent']").text()).toBe(
        "Enabled",
      );
      expect(wrapper.get("[data-testid='screen-perception-session']").text()).toBe(
        "Armed for this Life",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("keeps D25 configurable when local D23 consent is disabled", async () => {
    const { wrapper } = await mountSettings({
      localPolicy: makeLocalPolicy("life-a", false),
      outboundPolicy: null,
    });
    const createPolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "createPolicy")
      .mockResolvedValue(makeOutboundPolicy("life-a", false, 2));
    const updatePolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "updatePolicy")
      .mockResolvedValue(makeOutboundPolicy("life-a", true, 3));
    try {
      await wrapper.get("[data-testid='screen-vision-outbound-enable']").trigger("click");
      await flushMicrotasks();

      expect(createPolicy).toHaveBeenCalledTimes(1);
      expect(updatePolicy).toHaveBeenCalledTimes(1);
      expect(wrapper.get("[data-testid='screen-perception-consent']").text()).toBe(
        "Disabled",
      );
      expect(wrapper.find("[data-testid='screen-perception-arm']").exists()).toBe(false);
    } finally {
      wrapper.unmount();
    }
  });

  it("refreshes authoritatively after an ambiguous update failure without retrying mutation", async () => {
    const initial = makeOutboundPolicy("life-a", true, 4);
    const refreshed = makeOutboundPolicy("life-a", false, 5);
    const { wrapper, getOutboundPolicy } = await mountSettings({
      outboundPolicy: initial,
    });
    getOutboundPolicy.mockResolvedValueOnce(refreshed);
    const updatePolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "updatePolicy")
      .mockRejectedValue({
        code: "SCREEN_VISION_OUTBOUND_REVISION_CONFLICT",
        message: "raw backend details",
      });
    try {
      await wrapper.get("[data-testid='screen-vision-outbound-disable']").trigger("click");
      await flushMicrotasks();

      expect(updatePolicy).toHaveBeenCalledTimes(1);
      expect(getOutboundPolicy).toHaveBeenCalledTimes(2);
      expect(wrapper.get("[data-testid='screen-vision-outbound-status']").text()).toBe(
        "Disabled",
      );
      expect(wrapper.get("[data-testid='screen-vision-outbound-operation']").text()).toContain(
        "Current permission state was refreshed",
      );
      expect(wrapper.get("[data-testid='screen-vision-outbound-error']").text()).toContain(
        "latest permission state has been refreshed",
      );
      expect(wrapper.text()).not.toContain("raw backend details");
    } finally {
      wrapper.unmount();
    }
  });

  it("retains the last known policy when the authoritative reread fails", async () => {
    const initial = makeOutboundPolicy("life-a", true, 4);
    const { wrapper, getOutboundPolicy } = await mountSettings({
      outboundPolicy: initial,
    });
    getOutboundPolicy.mockRejectedValueOnce({
      code: "SCREEN_VISION_OUTBOUND_DATABASE_UNAVAILABLE",
      message: "private database path",
    });
    const updatePolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "updatePolicy")
      .mockRejectedValue({
        code: "SCREEN_VISION_OUTBOUND_POLICY_EVENT_CONFLICT",
        message: "private event details",
      });
    try {
      await wrapper.get("[data-testid='screen-vision-outbound-disable']").trigger("click");
      await flushMicrotasks();

      expect(updatePolicy).toHaveBeenCalledTimes(1);
      expect(getOutboundPolicy).toHaveBeenCalledTimes(2);
      expect(wrapper.get("[data-testid='screen-vision-outbound-status']").text()).toBe(
        "Enabled",
      );
      expect(wrapper.find("[data-testid='screen-vision-outbound-no-policy']").exists()).toBe(
        false,
      );
      expect(wrapper.get("[data-testid='screen-vision-outbound-operation']").text()).toContain(
        "could not be refreshed",
      );
      expect(wrapper.text()).not.toContain("private database path");
    } finally {
      wrapper.unmount();
    }
  });

  it("prevents a double click from starting concurrent mutations", async () => {
    const created = deferred<ScreenVisionOutboundPolicy>();
    const { wrapper } = await mountSettings({ outboundPolicy: null });
    const createPolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "createPolicy")
      .mockReturnValue(created.promise);
    const updatePolicy = vi.spyOn(
      screenVisionOutboundSettingsService,
      "updatePolicy",
    ).mockResolvedValue(makeOutboundPolicy("life-a", true, 10));
    try {
      const button = wrapper.get("[data-testid='screen-vision-outbound-enable']");
      await Promise.all([button.trigger("click"), button.trigger("click")]);
      expect(createPolicy).toHaveBeenCalledTimes(1);
      expect((button.element as HTMLButtonElement).disabled).toBe(true);

      created.resolve(makeOutboundPolicy("life-a", false, 9));
      await flushMicrotasks();
      expect(updatePolicy).toHaveBeenCalledTimes(1);
    } finally {
      wrapper.unmount();
    }
  });

  it("does not publish a delayed mutation result after unmount", async () => {
    const updateResult = deferred<ScreenVisionOutboundPolicy>();
    const { wrapper, getOutboundPolicy } = await mountSettings({
      outboundPolicy: makeOutboundPolicy("life-a", true, 2),
    });
    vi.spyOn(screenVisionOutboundSettingsService, "updatePolicy").mockReturnValue(
      updateResult.promise,
    );
    await wrapper.get("[data-testid='screen-vision-outbound-disable']").trigger("click");
    wrapper.unmount();
    updateResult.resolve(makeOutboundPolicy("life-a", false, 3));
    await flushMicrotasks();

    expect(getOutboundPolicy).toHaveBeenCalledTimes(1);
  });

  it("keeps stale policy results from a previous refresh from overwriting the current Life", async () => {
    const firstOutbound = deferred<ScreenVisionOutboundPolicy | null>();
    const lifeA = makeLife("life-a", "Life A");
    const lifeB = makeLife("life-b", "Life B");
    const getCurrentLife = vi
      .spyOn(storageService, "getCurrentLife")
      .mockResolvedValue(lifeA);
    vi.spyOn(screenPerceptionSettingsService, "getPolicy").mockResolvedValue(
      makeLocalPolicy("life-a", false),
    );
    vi.spyOn(screenPerceptionSettingsService, "getSessionStatus").mockResolvedValue({
      status: "disarmed",
    });
    vi.spyOn(screenCaptureSettingsService, "getTargetStatus").mockResolvedValue({
      status: "none",
    });
    const getOutboundPolicy = vi
      .spyOn(screenVisionOutboundSettingsService, "getPolicy")
      .mockReturnValue(firstOutbound.promise);
    const wrapper = mount(ScreenPerceptionSettingsView);
    await flushMicrotasks(4);

    getCurrentLife.mockResolvedValue(lifeB);
    getOutboundPolicy.mockResolvedValue(makeOutboundPolicy("life-b", true, 6));
    await wrapper.get("[data-testid='screen-perception-refresh']").trigger("click");
    await flushMicrotasks();
    expect(wrapper.get("[data-testid='screen-perception-current-life']").text()).toBe(
      "Life B",
    );
    expect(wrapper.get("[data-testid='screen-vision-outbound-status']").text()).toBe(
      "Enabled",
    );

    firstOutbound.resolve(makeOutboundPolicy("life-a", true, 99));
    await flushMicrotasks();
    expect(wrapper.get("[data-testid='screen-perception-current-life']").text()).toBe(
      "Life B",
    );
    expect(wrapper.get("[data-testid='screen-vision-outbound-revision']").text()).toBe(
      "6",
    );
    wrapper.unmount();
  });

  it("uses truthful local-versus-network copy without rendering internal IDs", async () => {
    const { wrapper } = await mountSettings({
      outboundPolicy: makeOutboundPolicy("life-a", true, 11),
    });
    try {
      expect(wrapper.text()).toContain(
        "Enabling this permission does not send any images by itself.",
      );
      expect(wrapper.text()).toContain("Cloud Vision image transmission is not active yet.");
      expect(wrapper.text()).toContain(
        "No screen image is being uploaded by this setting alone.",
      );
      expect(wrapper.text()).not.toContain("AI can now see the screen");
      expect(wrapper.text()).not.toContain("life-a");
      expect(wrapper.text()).not.toContain("eventId");
      expect(wrapper.text()).not.toContain("provider ID");
    } finally {
      wrapper.unmount();
    }
  });
});
