import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { invoke } from "@tauri-apps/api/core";
import CapabilitySettingsView from "../src/settings/capability/CapabilitySettingsView.vue";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const invokeMock = vi.mocked(invoke);

const CAPABILITY_ID = "vita.process.workspace.git_status";

function descriptor(overrides: Record<string, unknown> = {}) {
  return {
    capabilityId: CAPABILITY_ID,
    displayName: "Governed read-only workspace Git status",
    riskClass: "CRITICAL",
    approvalFloor: "EXPLICIT_PER_ACTION",
    scopeRequirement: "WORKSPACE_REQUIRED",
    readOnly: true,
    ...overrides,
  };
}

function entry(overrides: Record<string, unknown> = {}) {
  return {
    ...descriptor(),
    enabled: false,
    revision: 1,
    createdAt: "2026-09-12T00:00:00.000Z",
    updatedAt: "2026-09-12T00:00:00.000Z",
    recentAuthorizationEvents: [],
    ...overrides,
  };
}

function snapshot(entries: Record<string, unknown>[]) {
  return { lifeId: "life-1", capabilities: entries };
}

function auditEvent(overrides: Record<string, unknown> = {}) {
  return {
    oldEnabled: false,
    newEnabled: true,
    oldRevision: 1,
    newRevision: 2,
    changedAt: "2026-09-12T01:00:00.000Z",
    actorKind: "user_explicit",
    provenanceKind: "user_authorization_root",
    ...overrides,
  };
}

async function mountWith(snapshotValue: unknown) {
  invokeMock.mockResolvedValueOnce(snapshotValue);
  const wrapper = mount(CapabilitySettingsView);
  await flushPromises();
  return wrapper;
}

describe("CapabilitySettingsView", () => {
  beforeEach(() => {
    invokeMock.mockReset();
  });

  it("renders the disabled root state with trusted descriptor metadata", async () => {
    const wrapper = await mountWith(snapshot([entry()]));

    expect(invokeMock).toHaveBeenCalledWith("get_capability_authorization_snapshot");
    const card = wrapper.get(`[data-capability-id="${CAPABILITY_ID}"]`);
    expect(card.text()).toContain("Root disabled");
    expect(card.text()).toContain(CAPABILITY_ID);
    expect(card.text()).toContain("CRITICAL");
    expect(card.text()).toContain("EXPLICIT_PER_ACTION");
    expect(card.text()).toContain("WORKSPACE_REQUIRED");
    expect(card.text()).toContain("Read only");
    expect(wrapper.text()).toContain("Revision");
    wrapper.unmount();
  });

  it("explains that a root enable is not automatic execution", async () => {
    const wrapper = await mountWith(snapshot([entry()]));
    expect(wrapper.text()).toContain("Root enabled is not automatic execution");
    expect(wrapper.text()).toContain("explicit per-action confirmation");
    expect(wrapper.text()).toContain("single-use grant");
    wrapper.unmount();
  });

  it("shows the Critical explicit-per-action warning for the production capability", async () => {
    const wrapper = await mountWith(snapshot([entry()]));
    const warning = wrapper.get(`[data-warning-for="${CAPABILITY_ID}"]`);
    expect(warning.text()).toContain("Critical capability");
    expect(warning.text()).toContain("does not lower");
    wrapper.unmount();
  });

  it("requires a second explicit step before enabling and sends only the CAS triple", async () => {
    const wrapper = await mountWith(snapshot([entry()]));
    await wrapper.get("button.primary").trigger("click");
    await flushPromises();

    // The confirmation step appears and no transition has been sent yet.
    expect(wrapper.text()).toContain("Enable Governed read-only workspace Git status?");
    expect(wrapper.text()).toContain("Each use will still require your explicit confirmation");
    expect(invokeMock).not.toHaveBeenCalledWith(
      "set_capability_authorization_enabled",
      expect.anything(),
    );

    // Confirmation stays disabled until the user acknowledges.
    const confirm = wrapper
      .findAll("button")
      .find(button => button.text() === "Enable capability")!;
    expect(confirm.attributes("disabled")).toBeDefined();
    await wrapper.get('input[type="checkbox"]').setValue(true);
    await flushPromises();

    invokeMock.mockResolvedValueOnce({
      capabilityId: CAPABILITY_ID,
      enabled: true,
      revision: 2,
      previousEnabled: false,
      previousRevision: 1,
      transition: "applied",
      events: [auditEvent()],
    });
    invokeMock.mockResolvedValueOnce(snapshot([entry({ enabled: true, revision: 2 })]));
    await confirm.trigger("click");
    await flushPromises();

    expect(invokeMock).toHaveBeenCalledWith("set_capability_authorization_enabled", {
      capabilityId: CAPABILITY_ID,
      enabled: true,
      expectedRevision: 1,
    });
    // Refresh after success, and the new state is rendered.
    expect(invokeMock).toHaveBeenCalledWith("get_capability_authorization_snapshot");
    expect(wrapper.get(`[data-capability-id="${CAPABILITY_ID}"]`).text()).toContain(
      "Root enabled",
    );
    wrapper.unmount();
  });

  it("sends a disable transition with the observed revision and refreshes", async () => {
    const wrapper = await mountWith(snapshot([entry({ enabled: true, revision: 2 })]));

    invokeMock.mockResolvedValueOnce({
      capabilityId: CAPABILITY_ID,
      enabled: false,
      revision: 3,
      previousEnabled: true,
      previousRevision: 2,
      transition: "applied",
      events: [auditEvent({ oldEnabled: true, newEnabled: false, oldRevision: 2, newRevision: 3 })],
    });
    invokeMock.mockResolvedValueOnce(snapshot([entry({ enabled: false, revision: 3 })]));
    const disable = wrapper
      .findAll("button")
      .find(button => button.text() === "Disable capability")!;
    await disable.trigger("click");
    await flushPromises();

    expect(invokeMock).toHaveBeenCalledWith("set_capability_authorization_enabled", {
      capabilityId: CAPABILITY_ID,
      enabled: false,
      expectedRevision: 2,
    });
    expect(wrapper.get(`[data-capability-id="${CAPABILITY_ID}"]`).text()).toContain(
      "Root disabled",
    );
    wrapper.unmount();
  });

  it("refreshes and does not silently retry on a stale revision conflict", async () => {
    const wrapper = await mountWith(snapshot([entry()]));

    invokeMock.mockRejectedValueOnce({
      code: "CAPABILITY_ACTIVATION_REVISION_CONFLICT",
      message: "The capability authorization changed since it was loaded.",
    });
    invokeMock.mockResolvedValueOnce(snapshot([entry({ enabled: true, revision: 5 })]));

    await wrapper.get("button.primary").trigger("click");
    await flushPromises();
    await wrapper.get('input[type="checkbox"]').setValue(true);
    await flushPromises();
    const confirm = wrapper
      .findAll("button")
      .find(button => button.text() === "Enable capability")!;
    await confirm.trigger("click");
    await flushPromises();

    expect(wrapper.text()).toContain("changed elsewhere");
    expect(wrapper.text()).toContain("review the current state and try again");
    // The stale value is refreshed to the authoritative one.
    expect(wrapper.get(`[data-capability-id="${CAPABILITY_ID}"]`).text()).toContain("Root enabled");
    // Exactly one set attempt: the conflict was not retried automatically.
    const setCalls = invokeMock.mock.calls.filter(
      call => call[0] === "set_capability_authorization_enabled",
    );
    expect(setCalls).toHaveLength(1);
    wrapper.unmount();
  });

  it("reports a missing current Life as a fail-closed state", async () => {
    const wrapper = await mountWith(
      Promise.reject({
        code: "LIFE_NOT_AVAILABLE",
        message: "No current Life is available. Complete Life setup before managing capabilities.",
      }),
    );
    await flushPromises();
    expect(wrapper.text()).toContain("No current Life is available");
    expect(wrapper.text()).toContain("until Life setup is complete");
    wrapper.unmount();
  });

  it("surfaces an unexpected backend failure without losing the view", async () => {
    const wrapper = await mountWith(
      Promise.reject({
        code: "CAPABILITY_ACTIVATION_STORAGE_UNAVAILABLE",
        message: "The capability authorization store is unavailable.",
      }),
    );
    await flushPromises();
    // The first (snapshot) call rejected; a retry through Refresh renders the list again.
    expect(wrapper.text()).toContain("unavailable");
    invokeMock.mockResolvedValueOnce(snapshot([entry()]));
    const refresh = wrapper.findAll("button").find(button => button.text() === "Refresh")!;
    await refresh.trigger("click");
    await flushPromises();
    expect(wrapper.get(`[data-capability-id="${CAPABILITY_ID}"]`).text()).toContain(
      "Root disabled",
    );
    wrapper.unmount();
  });

  it("renders the immutable authorization history", async () => {
    const wrapper = await mountWith(
      snapshot([
        entry({
          enabled: false,
          revision: 3,
          recentAuthorizationEvents: [
            auditEvent({ oldEnabled: true, newEnabled: false, oldRevision: 2, newRevision: 3 }),
            auditEvent(),
          ],
        }),
      ]),
    );
    const card = wrapper.get(`[data-capability-id="${CAPABILITY_ID}"]`);
    expect(card.text()).toContain("Authorization history");
    expect(card.text()).toContain("Disabled");
    expect(card.text()).toContain("revision 2 → 3");
    expect(card.text()).toContain("Enabled");
    expect(card.text()).toContain("revision 1 → 2");
    expect(card.text()).toContain("user_explicit");
    expect(card.text()).toContain("user_authorization_root");
    expect(card.text()).toContain("immutable audit events");
    wrapper.unmount();
  });

  it("exposes no editable internal evidence field", async () => {
    const wrapper = await mountWith(
      snapshot([entry({ enabled: true, revision: 4, recentAuthorizationEvents: [auditEvent()] })]),
    );
    // The only interactive control is the enable acknowledgement checkbox.
    const editable = wrapper.findAll(
      "input:not([type='checkbox']), textarea, select, [contenteditable='true']",
    );
    expect(editable).toHaveLength(0);
    // No field is bound to internal evidence concepts.
    const html = wrapper.html();
    for (const forbidden of [
      "eventId",
      "lifeId-edit",
      "provenance",
      "processGrant",
      "expectedRevision-edit",
      "actorKind-edit",
      "executable",
      "argv",
    ]) {
      expect(html).not.toContain(`name="${forbidden}"`);
    }
    // The current Life is never submitted from the frontend.
    expect(html).not.toContain('name="lifeId"');
    wrapper.unmount();
  });
});
