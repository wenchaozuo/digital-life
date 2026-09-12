import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import VitaTurnPanel from "../src/settings/model/VitaTurnPanel.vue";
import { lifeIdentityManager } from "../src/life";
import { invoke } from "@tauri-apps/api/core";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }));
vi.mock("../src/life", () => ({
  lifeIdentityManager: { getCurrent: vi.fn() },
}));

const invokeMock = vi.mocked(invoke);
const currentLifeMock = vi.mocked(lifeIdentityManager.getCurrent);

function status(overrides: Record<string, unknown> = {}) {
  return {
    running: false,
    providerReadiness: "SIDECAR_NOT_RUNNING",
    capabilityReadiness: "ROOT_ENABLED",
    sessionLifeId: null,
    currentLifeId: null,
    sessionId: null,
    pending: null,
    activeTurnId: null,
    turnPhase: null,
    assistantText: null,
    turnError: null,
    ...overrides,
  };
}

describe("VitaTurnPanel", () => {
  beforeEach(() => {
    invokeMock.mockReset();
    currentLifeMock.mockReset();
  });

  it("locks the workspace and repeated cancellation while the session is cancelling", async () => {
    invokeMock.mockResolvedValue(
      status({
        running: true,
        providerReadiness: "READY",
        sessionId: "session",
        activeTurnId: "turn",
        turnPhase: "CANCELLING",
      }),
    );
    const wrapper = mount(VitaTurnPanel);
    await flushPromises();

    expect(wrapper.find("#vita-workspace").attributes("disabled")).toBeDefined();
    expect(wrapper.get("button.primary").text()).toContain("Start Vita turn");
    const choose = wrapper.find("button:not(.primary)");
    expect(choose.attributes("disabled")).toBeDefined();
    const cancel = wrapper.findAll("button").find(button => button.text() === "Cancelling…");
    expect(cancel).toBeDefined();
    expect(cancel!.attributes("disabled")).toBeDefined();
    wrapper.unmount();
  });

  it("fails before sidecar start when credential readiness is missing", async () => {
    invokeMock.mockResolvedValue(status({ providerReadiness: "CREDENTIAL_MISSING" }));
    const wrapper = mount(VitaTurnPanel);
    await wrapper.find("textarea").setValue("inspect status");
    await wrapper.findAll("button").find(button => button.text() === "Start Vita turn")!.trigger("click");
    await flushPromises();

    expect(invokeMock).toHaveBeenCalledWith("get_vita_sidecar_status");
    expect(invokeMock).not.toHaveBeenCalledWith("start_vita_sidecar", expect.anything());
    expect(wrapper.text()).toContain("Add a credential");
    expect(currentLifeMock).not.toHaveBeenCalled();
    wrapper.unmount();
  });

  it("renders a disabled capability root and blocks Start Turn without auto-enable", async () => {
    invokeMock.mockResolvedValue(status({ capabilityReadiness: "ROOT_DISABLED" }));
    const wrapper = mount(VitaTurnPanel);
    await wrapper.find("textarea").setValue("inspect status");
    await flushPromises();

    expect(wrapper.get("[data-testid='vita-capability-readiness']").text()).toContain("Disabled");
    expect(wrapper.text()).toContain("Enable the governed Git status capability in Agent permissions.");
    const start = wrapper.findAll("button").find(button => button.text() === "Start Vita turn");
    expect(start?.attributes("disabled")).toBeDefined();
    expect(wrapper.findAll("button").some(button => /Enable|Disable/.test(button.text()))).toBe(false);
    expect(invokeMock).not.toHaveBeenCalledWith("start_vita_sidecar", expect.anything());
    wrapper.unmount();
  });

  it("keeps provider readiness independent from an enabled capability root", async () => {
    invokeMock.mockResolvedValue(
      status({ capabilityReadiness: "ROOT_ENABLED", providerReadiness: "CREDENTIAL_MISSING" }),
    );
    const wrapper = mount(VitaTurnPanel);
    await flushPromises();

    expect(wrapper.get("[data-testid='vita-capability-readiness']").text()).toContain("Enabled");
    expect(wrapper.text()).toContain("Add a credential to the active Chat profile before starting Vita.");
    wrapper.unmount();
  });

  it("requires an explicit sidecar restart when the current Life changes", async () => {
    invokeMock.mockResolvedValue(
      status({
        running: true,
        providerReadiness: "READY",
        capabilityReadiness: "LIFE_RESTART_REQUIRED",
        sessionLifeId: "life-a",
        currentLifeId: "life-b",
      }),
    );
    const wrapper = mount(VitaTurnPanel);
    await wrapper.find("textarea").setValue("inspect status");
    await flushPromises();

    expect(wrapper.get("[data-testid='vita-capability-readiness']").text()).toContain("Restart required");
    expect(wrapper.text()).toContain("Current Life changed. Stop and restart Vita to bind the current Life.");
    const start = wrapper.findAll("button").find(button => button.text() === "Start Vita turn");
    expect(start?.attributes("disabled")).toBeDefined();
    wrapper.unmount();
  });
});
