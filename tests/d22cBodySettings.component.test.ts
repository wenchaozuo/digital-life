import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { LifeIdentity } from "../src/life";
import type { InstalledBodyPackageSnapshot } from "../src/body";

vi.mock("@tauri-apps/plugin-dialog", () => ({
  open: vi.fn(),
}));

function makeLife(bodyId: string): LifeIdentity {
  return {
    id: "life-1",
    name: "Life",
    createdAt: "2026-08-29T00:00:00.000Z",
    version: 2,
    bodyId,
    personaId: "persona-1",
    personaVersion: 1,
  };
}

function makePackage(): InstalledBodyPackageSnapshot {
  return {
    bodyId: "live2d-deadbeef",
    displayName: "Imported body",
    presentationKind: "live2d",
    modelEntry:
      "http://digital-life-body.localhost/live2d-deadbeef/avatar.model3.json",
    packageContentHash: "hash",
    packageVersion: 1,
    installedAt: "2026-08-29T00:00:00.000Z",
    status: "available",
    assets: [],
  };
}

async function flushMicrotasks(rounds = 12): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("D22-C Settings body section", () => {
  it("shows current Life.bodyId and managed package status without creating a renderer", async () => {
    vi.resetModules();
    const body = await import("../src/body");
    const storage = await import("../src/storage");
    const settingsModule = await import("../src/settings/SettingsApp.vue");
    let currentLife = makeLife("default-png");
    const managedPackage = makePackage();

    vi.spyOn(storage.storageService, "getStorageLocation").mockResolvedValue({
      currentDirectory: "C:/data",
      isDefaultDirectory: true,
    });
    vi.spyOn(storage.storageService, "getCurrentLife").mockImplementation(
      async () => currentLife,
    );
    vi.spyOn(body.bodyPackageService, "list").mockResolvedValue([managedPackage]);
    vi.spyOn(body.bodyPackageService, "setCurrentBody").mockImplementation(async (bodyId) => {
      currentLife = makeLife(bodyId);
      return currentLife;
    });

    const wrapper = mount(settingsModule.default);
    try {
      const bodySectionButton = wrapper
        .findAll("button")
        .find((button) => button.text() === "Body");
      expect(bodySectionButton).toBeDefined();
      await bodySectionButton?.trigger("click");
      await wrapper.vm.$nextTick();

      expect(wrapper.find("[aria-label='Body settings']").exists()).toBe(true);
      expect(wrapper.get("[data-testid='current-body-id']").text()).toBe("default-png");
      expect(wrapper.text()).toContain("Imported body");
      expect(wrapper.text()).toContain("available");
      expect(wrapper.find("canvas").exists()).toBe(false);

      await wrapper.get("[data-testid='body-package-live2d-deadbeef'] button").trigger("click");
      await wrapper.vm.$nextTick();
      expect(body.bodyPackageService.setCurrentBody).toHaveBeenCalledWith(
        "live2d-deadbeef",
      );
    } finally {
      wrapper.unmount();
    }
  });

  it("supports cancelled import and passes only the selected path to install", async () => {
    vi.resetModules();
    const dialog = await import("@tauri-apps/plugin-dialog");
    const body = await import("../src/body");
    const storage = await import("../src/storage");
    const settingsModule = await import("../src/settings/SettingsApp.vue");
    const selectedPath = "C:\\bodies\\Aurora.model3.json";
    const managedPackage = makePackage();

    vi.spyOn(dialog, "open")
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(selectedPath);
    vi.spyOn(storage.storageService, "getStorageLocation").mockResolvedValue({
      currentDirectory: "C:/data",
      isDefaultDirectory: true,
    });
    vi.spyOn(storage.storageService, "getCurrentLife").mockResolvedValue(
      makeLife("default-png"),
    );
    vi.spyOn(body.bodyPackageService, "list").mockResolvedValue([]);
    const install = vi
      .spyOn(body.bodyPackageService, "install")
      .mockResolvedValue(managedPackage);

    const wrapper = mount(settingsModule.default);
    try {
      const bodySectionButton = wrapper
        .findAll("button")
        .find((button) => button.text() === "Body");
      await bodySectionButton?.trigger("click");
      await wrapper.vm.$nextTick();

      const importButton = () =>
        wrapper.findAll("button").find((button) => button.text() === "Choose model3.json");
      await importButton()?.trigger("click");
      await importButton()?.trigger("click");
      const confirmImport = wrapper
        .findAll("button")
        .find((button) => button.text() === "Import body");
      expect(confirmImport).toBeDefined();
      await confirmImport?.trigger("click");
      await flushMicrotasks();

      expect(install).toHaveBeenCalledTimes(1);
      expect(install).toHaveBeenCalledWith({
        sourcePath: selectedPath,
        displayName: "Aurora",
      });
      expect(wrapper.text()).not.toContain(selectedPath);
    } finally {
      wrapper.unmount();
    }
  });

  it("shows corrupt status, reports in-use deletion, and selects default PNG explicitly", async () => {
    vi.resetModules();
    const body = await import("../src/body");
    const storage = await import("../src/storage");
    const settingsModule = await import("../src/settings/SettingsApp.vue");
    const managedPackage = makePackage();
    const corruptPackage = { ...managedPackage, bodyId: "live2d-c0ffee", status: "corrupt-unavailable" as const };
    let currentLife = makeLife(managedPackage.bodyId);

    vi.spyOn(storage.storageService, "getStorageLocation").mockResolvedValue({
      currentDirectory: "C:/data",
      isDefaultDirectory: true,
    });
    vi.spyOn(storage.storageService, "getCurrentLife").mockImplementation(
      async () => currentLife,
    );
    vi.spyOn(body.bodyPackageService, "list").mockResolvedValue([
      managedPackage,
      corruptPackage,
    ]);
    const setCurrent = vi
      .spyOn(body.bodyPackageService, "setCurrentBody")
      .mockImplementation(async (bodyId) => {
        currentLife = makeLife(bodyId);
        return currentLife;
      });
    const deleteBody = vi.spyOn(body.bodyPackageService, "delete").mockRejectedValue({
      code: "BODY_PACKAGE_IN_USE",
      message: "The body package is still referenced by a Life identity.",
    });

    const wrapper = mount(settingsModule.default);
    try {
      const bodySectionButton = wrapper
        .findAll("button")
        .find((button) => button.text() === "Body");
      await bodySectionButton?.trigger("click");
      await wrapper.vm.$nextTick();
      expect(wrapper.text()).toContain("corrupt-unavailable");
      expect(
        wrapper
          .get("[data-testid='body-package-live2d-c0ffee']")
          .find("button")
          .attributes("disabled"),
      ).toBeDefined();

      await wrapper
        .get("[data-testid='body-package-live2d-deadbeef'] .danger")
        .trigger("click");
      await wrapper.vm.$nextTick();
      expect(wrapper.text()).toContain("BODY_PACKAGE_IN_USE");

      await wrapper
        .get("[data-testid='default-body-package'] button")
        .trigger("click");
      expect(setCurrent).toHaveBeenCalledWith("default-png");

      deleteBody.mockResolvedValue();
      await wrapper
        .get("[data-testid='body-package-live2d-deadbeef'] .danger")
        .trigger("click");
      await flushMicrotasks();
      expect(deleteBody).toHaveBeenLastCalledWith("live2d-deadbeef");
    } finally {
      wrapper.unmount();
    }
  });
});
