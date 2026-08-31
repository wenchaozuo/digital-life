import fs from "node:fs";
import path from "node:path";

import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { LifeIdentity } from "../src/life";
import type {
  ScreenPerceptionPolicy,
  ScreenPerceptionSessionStatus,
} from "../src/settings/perception/screenPerceptionSettingsService";

function makeLife(id = "life-a", name = "Life A"): LifeIdentity {
  return {
    id,
    name,
    createdAt: "2026-08-29T00:00:00.000Z",
    version: 1,
    bodyId: "default-png",
    personaId: "persona-1",
    personaVersion: 1,
  };
}

function makePolicy(
  lifeId = "life-a",
  enabled = true,
  revision = 1,
): ScreenPerceptionPolicy {
  return {
    lifeId,
    enabled,
    revision,
    createdAt: "2026-08-29T00:00:00.000Z",
    updatedAt: "2026-08-29T00:00:00.000Z",
  };
}

async function flushMicrotasks(rounds = 12): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

async function mountPerception(options: {
  life?: LifeIdentity;
  policy?: ScreenPerceptionPolicy | null;
  session?: ScreenPerceptionSessionStatus;
} = {}) {
  vi.resetModules();
  const storage = await import("../src/storage");
  const perception = await import(
    "../src/settings/perception/screenPerceptionSettingsService"
  );
  const outbound = await import(
    "../src/settings/perception/screenVisionOutboundSettingsService"
  );
  const settingsModule = await import("../src/settings/SettingsApp.vue");

  vi.spyOn(storage.storageService, "getStorageLocation").mockResolvedValue({
    currentDirectory: "C:/data",
    isDefaultDirectory: true,
  });
  vi.spyOn(storage.storageService, "getCurrentLife").mockResolvedValue(
    options.life ?? makeLife(),
  );
  const getPolicy = vi
    .spyOn(perception.screenPerceptionSettingsService, "getPolicy")
    .mockResolvedValue(options.policy === undefined ? makePolicy() : options.policy);
  const getSessionStatus = vi
    .spyOn(perception.screenPerceptionSettingsService, "getSessionStatus")
    .mockResolvedValue(options.session ?? { status: "disarmed" });
  vi.spyOn(outbound.screenVisionOutboundSettingsService, "getPolicy").mockResolvedValue(
    null,
  );

  const wrapper = mount(settingsModule.default);
  const sectionButton = wrapper
    .findAll("button")
    .find((button) => button.text() === "Screen privacy");
  expect(sectionButton).toBeDefined();
  await sectionButton?.trigger("click");
  await wrapper.vm.$nextTick();
  await flushMicrotasks();

  return {
    wrapper,
    perception,
    getPolicy,
    getSessionStatus,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("D23-B2 Settings screen-perception authority", () => {
  it("reads policy and session without auto-arming on mount", async () => {
    const { wrapper, perception, getPolicy, getSessionStatus } =
      await mountPerception();
    const armSession = vi
      .spyOn(perception.screenPerceptionSettingsService, "armSession")
      .mockResolvedValue({ status: "armed", lifeId: "life-a" });
    try {
      expect(getPolicy).toHaveBeenCalledWith("life-a");
      expect(getSessionStatus).toHaveBeenCalledTimes(1);
      expect(armSession).not.toHaveBeenCalled();
      expect(wrapper.get("[data-testid='screen-perception-consent']").text()).toBe(
        "Enabled",
      );
      expect(wrapper.get("[data-testid='screen-perception-session']").text()).toBe(
        "Disarmed",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("creates first-time consent without auto-arming, then arms only explicitly", async () => {
    const { wrapper, perception } = await mountPerception({ policy: null });
    const createPolicy = vi
      .spyOn(perception.screenPerceptionSettingsService, "createPolicy")
      .mockResolvedValue(makePolicy());
    const armSession = vi
      .spyOn(perception.screenPerceptionSettingsService, "armSession")
      .mockResolvedValue({ status: "armed", lifeId: "life-a" });
    try {
      await wrapper.get("[data-testid='screen-perception-enable']").trigger("click");
      await flushMicrotasks();
      expect(createPolicy).toHaveBeenCalledWith("life-a", true);
      expect(armSession).not.toHaveBeenCalled();
      expect(wrapper.get("[data-testid='screen-perception-consent']").text()).toBe(
        "Enabled",
      );
      expect(wrapper.get("[data-testid='screen-perception-arm']").exists()).toBe(true);

      await wrapper.get("[data-testid='screen-perception-arm']").trigger("click");
      await flushMicrotasks();
      expect(armSession).toHaveBeenCalledWith("life-a");
      expect(wrapper.get("[data-testid='screen-perception-session']").text()).toBe(
        "Armed for this Life",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("blocks arming while consent is disabled and supports explicit disarm", async () => {
    const { wrapper, perception } = await mountPerception({
      policy: makePolicy("life-a", false),
      session: { status: "disarmed" },
    });
    const updatePolicy = vi
      .spyOn(perception.screenPerceptionSettingsService, "updatePolicy")
      .mockResolvedValue(makePolicy("life-a", true, 2));
    const disarmSession = vi
      .spyOn(perception.screenPerceptionSettingsService, "disarmSession")
      .mockResolvedValue({ status: "disarmed" });
    const armSession = vi
      .spyOn(perception.screenPerceptionSettingsService, "armSession")
      .mockResolvedValue({ status: "armed", lifeId: "life-a" });
    try {
      expect(wrapper.get("[data-testid='screen-perception-consent']").text()).toBe(
        "Disabled",
      );
      expect(wrapper.find("[data-testid='screen-perception-arm']").exists()).toBe(false);

      await wrapper.get("[data-testid='screen-perception-enable']").trigger("click");
      await flushMicrotasks();
      expect(updatePolicy).toHaveBeenCalledWith("life-a", true, 1);
      expect(armSession).not.toHaveBeenCalled();
      expect(wrapper.get("[data-testid='screen-perception-arm']").exists()).toBe(true);

      await wrapper.get("[data-testid='screen-perception-arm']").trigger("click");
      await flushMicrotasks();
      expect(armSession).toHaveBeenCalledWith("life-a");

      await wrapper.get("[data-testid='screen-perception-disarm']").trigger("click");
      await flushMicrotasks();
      expect(disarmSession).toHaveBeenCalledTimes(1);
      expect(wrapper.get("[data-testid='screen-perception-session']").text()).toBe(
        "Disarmed",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("shows Life A session ownership as inactive while Settings displays Life B", async () => {
    const { wrapper, perception } = await mountPerception({
      life: makeLife("life-b", "Life B"),
      policy: makePolicy("life-b", true),
      session: { status: "armed", lifeId: "life-a" },
    });
    const armSession = vi
      .spyOn(perception.screenPerceptionSettingsService, "armSession")
      .mockResolvedValue({ status: "armed", lifeId: "life-b" });
    try {
      expect(wrapper.get("[data-testid='screen-perception-session']").text()).toBe(
        "Armed for another Life",
      );
      expect(wrapper.get("[data-testid='screen-perception-life-mismatch']").text()).toContain(
        "not active for this Life",
      );
      expect(wrapper.get("[data-testid='screen-perception-armed-life']").text()).toContain(
        "life-a",
      );

      await wrapper.get("[data-testid='screen-perception-arm']").trigger("click");
      await flushMicrotasks();
      expect(armSession).toHaveBeenCalledWith("life-b");
    } finally {
      wrapper.unmount();
    }
  });

  it("maps revision conflicts and unknown backend failures to bounded UI feedback", async () => {
    const { wrapper, perception } = await mountPerception();
    const updatePolicy = vi
      .spyOn(perception.screenPerceptionSettingsService, "updatePolicy")
      .mockRejectedValue({
        code: "SCREEN_PERCEPTION_REVISION_CONFLICT",
        message: "C:/private/raw.sqlite3",
      });
    try {
      await wrapper.get("[data-testid='screen-perception-disable']").trigger("click");
      await flushMicrotasks();
      expect(updatePolicy).toHaveBeenCalledWith("life-a", false, 1);
      expect(wrapper.get("[data-testid='screen-perception-error']").text()).toContain(
        "Refresh the policy and retry the action.",
      );
      expect(wrapper.text()).not.toContain("raw.sqlite3");

      updatePolicy.mockRejectedValue({
        code: "DATABASE_ERROR",
        message: "C:/private/secret.sqlite3",
      });
      await wrapper.get("[data-testid='screen-perception-disable']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.get("[data-testid='screen-perception-error']").text()).toContain(
        "settings could not be updated",
      );
      expect(wrapper.text()).not.toContain("secret.sqlite3");
    } finally {
      wrapper.unmount();
    }
  });

  it("renders the no-policy state without exposing an arm action", async () => {
    const { wrapper, perception } = await mountPerception({ policy: null });
    const armSession = vi
      .spyOn(perception.screenPerceptionSettingsService, "armSession")
      .mockResolvedValue({ status: "armed", lifeId: "life-a" });
    try {
      expect(wrapper.get("[data-testid='screen-perception-no-policy']").exists()).toBe(true);
      expect(wrapper.get("[data-testid='screen-perception-consent']").text()).toBe(
        "Not configured",
      );
      expect(wrapper.find("[data-testid='screen-perception-arm']").exists()).toBe(false);
      expect(armSession).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
    }
  });

  it("keeps the new command authority in Settings only", () => {
    const read = (file: string) =>
      fs.readFileSync(path.join(process.cwd(), file), "utf8");
    const settings = read("src-tauri/permissions/settings-commands.toml");
    const main = read("src-tauri/permissions/main-commands.toml");
    const chat = read("src-tauri/permissions/chat-commands.toml");
    const commands = [
      "get_screen_perception_policy",
      "create_screen_perception_policy",
      "update_screen_perception_policy",
      "get_screen_perception_session_status",
      "arm_screen_perception_session",
      "disarm_screen_perception_session",
    ];
    for (const command of commands) {
      expect(settings).toContain(`"${command}"`);
      expect(main).not.toContain(`"${command}"`);
      expect(chat).not.toContain(`"${command}"`);
    }
  });
});
