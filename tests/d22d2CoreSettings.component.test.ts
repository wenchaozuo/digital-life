import fs from "node:fs";
import path from "node:path";

import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { LifeIdentity } from "../src/life";

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
}));

function makeLife(): LifeIdentity {
  return {
    id: "life-1",
    name: "Life",
    createdAt: "2026-08-29T00:00:00.000Z",
    version: 2,
    bodyId: "default-png",
    personaId: "persona-1",
    personaVersion: 1,
  };
}

function snapshot(
  status: "not-configured" | "ready-for-startup" | "corrupt-unavailable" = "not-configured",
  restartRequired = false,
) {
  return {
    status,
    runtimeFamily: "cubism4" as const,
    versionLabel: status === "not-configured" ? undefined : "5-r.5",
    sha256:
      status === "not-configured"
        ? undefined
        : "8741f739779b5d5210872bd3d7d99f0f1e56e6c87409e7d26d6bb4b80aa1ef47",
    scriptUrl: status === "ready-for-startup" ? "http://digital-life-core.localhost/live2dcubismcore.min.js" : undefined,
    restartRequired,
  };
}

async function flushMicrotasks(rounds = 12): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

async function mountCoreSettings() {
  vi.resetModules();
  const dialog = await import("@tauri-apps/plugin-dialog");
  const storage = await import("../src/storage");
  const core = await import("../src/settings/core/live2dCoreSettingsService");
  const settingsModule = await import("../src/settings/SettingsApp.vue");

  vi.spyOn(storage.storageService, "getStorageLocation").mockResolvedValue({
    currentDirectory: "C:/data",
    isDefaultDirectory: true,
  });
  vi.spyOn(storage.storageService, "getCurrentLife").mockResolvedValue(makeLife());
  const getSnapshot = vi
    .spyOn(core.live2dCoreSettingsService, "getSnapshot")
    .mockResolvedValue(snapshot());

  const wrapper = mount(settingsModule.default);
  const coreButton = wrapper
    .findAll("button")
    .find((button) => button.text() === "Live2D Core");
  await coreButton?.trigger("click");
  await wrapper.vm.$nextTick();
  await flushMicrotasks();

  return { wrapper, dialog, core, getSnapshot };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("D22-D2 Live2D Core Settings", () => {
  it("shows authoritative status, version, restart state, and no renderer", async () => {
    const { wrapper, getSnapshot } = await mountCoreSettings();
    getSnapshot.mockResolvedValue(snapshot("ready-for-startup"));
    getSnapshot.mockClear();
    try {
      await wrapper.get("[data-testid='refresh-cubism-core']").trigger("click");
      await flushMicrotasks();
      expect(getSnapshot).toHaveBeenCalledTimes(1);
      expect(wrapper.get("[data-testid='live2d-core-status']").text()).toBe("Ready for startup");
      expect(wrapper.get("[data-testid='live2d-core-version']").text()).toBe("5-r.5");
      expect(wrapper.get("[data-testid='live2d-core-restart-required']").text()).toBe("No");
      expect(wrapper.find("canvas").exists()).toBe(false);
      expect(wrapper.text()).not.toContain("new Live2DRenderer");
    } finally {
      wrapper.unmount();
    }
  });

  it("handles picker cancel and enforces the exact Core filename", async () => {
    const { wrapper, dialog, core } = await mountCoreSettings();
    const open = vi.mocked(dialog.open);
    const install = vi.spyOn(core.live2dCoreSettingsService, "install");
    open.mockResolvedValueOnce(null).mockResolvedValueOnce("C:\\temp\\other.js");
    try {
      const button = wrapper.get("[data-testid='install-cubism-core']");
      await button.trigger("click");
      await button.trigger("click");
      await flushMicrotasks();
      expect(install).not.toHaveBeenCalled();
      expect(wrapper.text()).toContain("LIVE2D_CORE_INVALID_INPUT");
      expect(open).toHaveBeenNthCalledWith(
        1,
        expect.objectContaining({ directory: false, multiple: false }),
      );
      expect(open.mock.calls[0]?.[0]).toMatchObject({
        filters: [{ name: "Cubism Core", extensions: ["js"] }],
      });
    } finally {
      wrapper.unmount();
    }
  });

  it("installs an approved Core, shows restart required, and discards the source path", async () => {
    const { wrapper, dialog, core } = await mountCoreSettings();
    const selectedPath = "C:\\sdk\\live2dcubismcore.min.js";
    vi.mocked(dialog.open).mockResolvedValue(selectedPath);
    const install = vi
      .spyOn(core.live2dCoreSettingsService, "install")
      .mockResolvedValue(snapshot("ready-for-startup", true));
    try {
      await wrapper.get("[data-testid='install-cubism-core']").trigger("click");
      await flushMicrotasks();
      expect(install).toHaveBeenCalledWith(selectedPath);
      expect(wrapper.get("[data-testid='live2d-core-version']").text()).toBe("5-r.5");
      expect(wrapper.get("[data-testid='live2d-core-restart-required']").text()).toBe("Yes");
      expect(wrapper.text()).toContain("Verified Cubism Core installed.");
      expect(wrapper.text()).toContain("full application exit and restart");
      expect(wrapper.text()).not.toContain(selectedPath);
    } finally {
      wrapper.unmount();
    }
  });

  it("maps unapproved input and corrupt status to bounded feedback", async () => {
    const { wrapper, dialog, core, getSnapshot } = await mountCoreSettings();
    getSnapshot.mockResolvedValue(snapshot("corrupt-unavailable"));
    vi.mocked(dialog.open).mockResolvedValue("C:\\sdk\\live2dcubismcore.min.js");
    vi.spyOn(core.live2dCoreSettingsService, "install").mockRejectedValue({
      code: "LIVE2D_CORE_UNAPPROVED",
      message: "C:\\private\\secret\\evil.js",
    });
    try {
      await wrapper.get("[data-testid='refresh-cubism-core']").trigger("click");
      await wrapper.get("[data-testid='install-cubism-core']").trigger("click");
      await flushMicrotasks();
      expect(wrapper.get("[data-testid='live2d-core-status']").text()).toBe("Corrupt / unavailable");
      expect(wrapper.text()).toContain("LIVE2D_CORE_UNAPPROVED");
      expect(wrapper.text()).toContain("not an approved Cubism Core");
      expect(wrapper.text()).not.toContain("secret");
    } finally {
      wrapper.unmount();
    }
  });

  it("keeps Core commands confined to Settings and Main snapshot access", () => {
    const read = (file: string) =>
      fs.readFileSync(path.join(process.cwd(), file), "utf8");
    const settings = read("src-tauri/permissions/settings-commands.toml");
    const main = read("src-tauri/permissions/main-commands.toml");
    const chat = read("src-tauri/permissions/chat-commands.toml");
    expect(settings).toContain('"import_cubism_core"');
    expect(settings).toContain('"get_cubism_core_snapshot"');
    expect(main).toContain('"get_cubism_core_snapshot"');
    expect(main).not.toContain('"import_cubism_core"');
    expect(chat).not.toContain('"import_cubism_core"');
    expect(chat).not.toContain('"get_cubism_core_snapshot"');
  });

  it("keeps Settings free of Core execution and raw model authority", () => {
    const settingsSource = fs.readFileSync(
      path.join(process.cwd(), "src/settings/core/Live2DCoreSettingsView.vue"),
      "utf8",
    );
    expect(settingsSource).toContain("Install Cubism Core");
    expect(settingsSource).not.toMatch(/Live2DRenderer|createPixi|<canvas|model3\.json/);
    expect(settingsSource).not.toContain("digital-life-core");
  });
});
