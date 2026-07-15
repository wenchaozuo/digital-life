import { afterEach, describe, expect, it } from "vitest";
import { mount, type VueWrapper } from "@vue/test-utils";
import CandidateConfirmationDialog from "../src/chat/components/CandidateConfirmationDialog.vue";
import {
  CandidateConfirmationError,
  type PreparedCandidateConfirmationPreview,
} from "../src/memory/candidateConfirmationTypes.ts";
import type { CandidateConfirmationPhase } from "../src/stores/candidateConfirmation.ts";

function preview(
  overrides: Partial<PreparedCandidateConfirmationPreview> = {},
): PreparedCandidateConfirmationPreview {
  return {
    candidateId: "candidate-a",
    expectedRevision: 4,
    kind: "preference",
    content: "Keep answers concise.",
    summary: "Response preference",
    isSensitive: false,
    source: "conversation",
    confirmationRequirement: "standard",
    expiresAt: "2030-01-01T00:00:00.000Z",
    ...overrides,
  };
}

function mountDialog(options: {
  open?: boolean;
  prepared?: PreparedCandidateConfirmationPreview | null;
  phase?: CandidateConfirmationPhase;
  error?: CandidateConfirmationError | null;
  cancelOutcomeUnknown?: boolean;
  isReloadingAuthoritativeState?: boolean;
  authoritativeReloadFailed?: boolean;
} = {}): VueWrapper {
  return mount(CandidateConfirmationDialog, {
    attachTo: document.body,
    props: {
      open: options.open ?? true,
      prepared: options.prepared ?? preview(),
      phase: options.phase ?? "prepared",
      error: options.error ?? null,
      cancelOutcomeUnknown: options.cancelOutcomeUnknown ?? false,
      isReloadingAuthoritativeState: options.isReloadingAuthoritativeState ?? false,
      authoritativeReloadFailed: options.authoritativeReloadFailed ?? false,
    },
  });
}

afterEach(() => {
  document.body.innerHTML = "";
});

describe("CandidateConfirmationDialog", () => {
  it("renders a token-free preview and normal confirmation controls", async () => {
    const wrapper = mountDialog();
    await wrapper.vm.$nextTick();

    expect(wrapper.find("dialog").attributes("open")).toBeDefined();
    expect(wrapper.find(".preview-fields").text()).toContain("Keep answers concise.");
    expect(wrapper.find(".btn-confirm").exists()).toBe(true);
    expect(wrapper.html()).not.toContain("approvalToken");
  });

  it("uses the sensitive confirmation control only when the backend requires it", () => {
    const wrapper = mountDialog({
      prepared: preview({
        isSensitive: true,
        confirmationRequirement: "explicitSensitiveApproval",
      }),
    });

    expect(wrapper.find(".sensitive-warning-banner").exists()).toBe(true);
    expect(wrapper.find(".btn-confirm-sensitive").exists()).toBe(true);
    expect(wrapper.find(".btn-confirm").exists()).toBe(false);
  });

  it("renders safe placeholders for null content and summary while retaining source and kind fields", () => {
    const wrapper = mountDialog({
      prepared: preview({ content: null, summary: null, source: "external-import" }),
    });

    expect(wrapper.findAll(".field-content")).toHaveLength(2);
    expect(wrapper.findAll(".field-content")[0].text()).not.toBe("");
    expect(wrapper.findAll(".field-content")[1].text()).not.toBe("");
    expect(wrapper.find(".kind-badge").text()).not.toBe("");
    expect(wrapper.text()).toContain("external-import");
  });

  it("emits confirmation intent once without carrying a token", async () => {
    const wrapper = mountDialog();

    await wrapper.find(".btn-confirm").trigger("click");

    expect(wrapper.emitted("confirm")).toHaveLength(1);
    expect(wrapper.emitted("confirm")?.[0]).toEqual([]);
  });

  it("emits cancel for an explicit cancel action", async () => {
    const wrapper = mountDialog();

    await wrapper.find(".btn-cancel").trigger("click");

    expect(wrapper.emitted("cancel")).toHaveLength(1);
  });

  it("treats close, backdrop, and Escape as cancellation while authorization exists", async () => {
    const closeWrapper = mountDialog();
    await closeWrapper.find(".close-btn").trigger("click");
    expect(closeWrapper.emitted("cancel")).toHaveLength(1);

    const backdropWrapper = mountDialog();
    await backdropWrapper.find(".dialog-backdrop").trigger("click");
    expect(backdropWrapper.emitted("cancel")).toHaveLength(1);

    const escapeWrapper = mountDialog();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    expect(escapeWrapper.emitted("cancel")).toHaveLength(1);
  });

  it("does not close or cancel while confirm/cancel requests are in flight", async () => {
    const confirming = mountDialog({ phase: "confirming" });
    await confirming.find(".close-btn").trigger("click");
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    expect(confirming.emitted("cancel")).toBeUndefined();
    expect(confirming.emitted("close")).toBeUndefined();

    const cancelling = mountDialog({ phase: "cancelling" });
    await cancelling.find(".dialog-backdrop").trigger("click");
    expect(cancelling.emitted("cancel")).toBeUndefined();
    expect(cancelling.emitted("close")).toBeUndefined();
  });

  it("allows a preparing dialog to close without attempting cancellation", async () => {
    const wrapper = mountDialog({ prepared: null, phase: "preparing" });

    await wrapper.find(".close-btn").trigger("click");

    expect(wrapper.emitted("close")).toHaveLength(1);
    expect(wrapper.emitted("cancel")).toBeUndefined();
  });

  it("renders failure details even after the Store has cleared its preview", () => {
    const wrapper = mountDialog({
      prepared: null,
      phase: "failed",
      error: new CandidateConfirmationError(
        "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
        "The approval token has expired.",
        "reprepare",
      ),
    });

    expect(wrapper.find(".error-banner").exists()).toBe(true);
    expect(wrapper.find(".error-actions .btn-secondary").exists()).toBe(true);
  });

  it("routes retry actions according to the Store-provided error action", async () => {
    const sameToken = mountDialog({
      phase: "prepared",
      error: new CandidateConfirmationError(
        "CANDIDATE_CONFIRMATION_STORAGE_UNAVAILABLE",
        "Storage is temporarily unavailable.",
        "retrySameToken",
      ),
    });
    await sameToken.find(".error-actions .btn-secondary").trigger("click");
    expect(sameToken.emitted("retryConfirm")).toHaveLength(1);
    expect(sameToken.emitted("retryPrepare")).toBeUndefined();

    const reprepare = mountDialog({
      prepared: null,
      phase: "failed",
      error: new CandidateConfirmationError(
        "CANDIDATE_CONFIRMATION_TOKEN_EXPIRED",
        "The approval token has expired.",
        "reprepare",
      ),
    });
    await reprepare.find(".error-actions .btn-secondary").trigger("click");
    expect(reprepare.emitted("retryPrepare")).toHaveLength(1);

    const later = mountDialog({
      prepared: null,
      phase: "failed",
      error: new CandidateConfirmationError(
        "CANDIDATE_CONFIRMATION_TEMPORARILY_UNAVAILABLE",
        "The service is temporarily unavailable.",
        "retryPrepareLater",
      ),
    });
    await later.find(".error-actions .btn-secondary").trigger("click");
    expect(later.emitted("retryPrepare")).toHaveLength(1);
  });

  it("does not offer a retry when the Store marks an error as non-recoverable", () => {
    const wrapper = mountDialog({
      prepared: null,
      phase: "failed",
      error: new CandidateConfirmationError(
        "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
        "The confirmation operation failed.",
        "none",
      ),
    });

    expect(wrapper.find(".error-actions .btn-secondary").text()).toContain("关闭");
  });

  it("offers only an explicit authoritative reload for an uncertain cancellation", async () => {
    const wrapper = mountDialog({
      prepared: null,
      phase: "failed",
      error: new CandidateConfirmationError(
        "CANDIDATE_CONFIRMATION_INTERNAL_ERROR",
        "The confirmation operation failed.",
        "none",
      ),
      cancelOutcomeUnknown: true,
    });

    expect(wrapper.find(".uncertain-cancel-banner").exists()).toBe(true);
    expect(wrapper.find(".reload-authoritative-state").text()).toContain("重新加载候选状态");
    expect(wrapper.find(".uncertain-cancel-close").text()).toContain("关闭");
    expect(wrapper.text()).not.toContain("取消成功");
    expect(wrapper.html()).not.toContain("approvalToken");

    await wrapper.find(".reload-authoritative-state").trigger("click");
    await wrapper.find(".uncertain-cancel-close").trigger("click");

    expect(wrapper.emitted("reloadAuthoritativeState")).toHaveLength(1);
    expect(wrapper.emitted("close")).toHaveLength(1);
    expect(wrapper.emitted("confirm")).toBeUndefined();
    expect(wrapper.emitted("cancel")).toBeUndefined();
  });

  it("blocks duplicate authoritative reload intent while a reload is in progress", async () => {
    const wrapper = mountDialog({
      prepared: null,
      phase: "failed",
      cancelOutcomeUnknown: true,
      isReloadingAuthoritativeState: true,
    });

    const reload = wrapper.find(".reload-authoritative-state");
    expect(reload.attributes("disabled")).toBeDefined();
    await reload.trigger("click");
    expect(wrapper.emitted("reloadAuthoritativeState")).toBeUndefined();
  });

  it("exposes dialog semantics and restores focus after closing", async () => {
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();
    const wrapper = mountDialog();
    await wrapper.vm.$nextTick();

    expect(wrapper.find("dialog").attributes("role")).toBe("dialog");
    expect(wrapper.find("dialog").attributes("aria-modal")).toBe("true");
    const labelledBy = wrapper.find("dialog").attributes("aria-labelledby");
    expect(document.getElementById(labelledBy)).not.toBeNull();
    expect(document.activeElement).toBe(wrapper.find(".close-btn").element);

    await wrapper.setProps({ open: false });
    expect(document.activeElement).toBe(trigger);
  });

  it("uses busy/status semantics for in-flight operations and removes its Escape listener on unmount", async () => {
    const wrapper = mountDialog({ phase: "confirming" });
    expect(wrapper.find("dialog").attributes("aria-busy")).toBe("true");
    expect(wrapper.find(".dialog-loading[role='status']").exists()).toBe(true);

    wrapper.unmount();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    expect(wrapper.emitted("cancel")).toBeUndefined();
  });
});
