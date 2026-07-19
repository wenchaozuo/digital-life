import { describe, expect, it, vi } from "vitest";
import { mount } from "@vue/test-utils";
import ModelProfileCard from "../src/settings/model/ModelProfileCard.vue";
import ModelProfileForm from "../src/settings/model/ModelProfileForm.vue";
import type { ModelProfile } from "../src/model/modelProfileService.ts";

function createCandidateProfile(overrides: Partial<ModelProfile> = {}): ModelProfile {
  return {
    id: "candidate-prof",
    purpose: "candidate_extraction",
    providerKind: "openai_compatible",
    displayName: "Candidate Profile",
    baseUrl: "https://candidate.example/v1",
    modelName: "candidate-model",
    temperature: 0.0,
    maxTokens: 2048,
    embeddingDimension: null,
    createdAt: "2026-07-19T00:00:00Z",
    updatedAt: "2026-07-19T00:00:00Z",
    ...overrides,
  };
}

describe("ModelProfileCard component", () => {
  it("renders candidate profile list item with Max tokens and without Test connection button", () => {
    const profile = createCandidateProfile();
    const wrapper = mount(ModelProfileCard, {
      props: {
        profile,
        active: true,
        runtime: { state: "idle", credentialExists: true },
        clearEpoch: 1,
        onSaveCredential: vi.fn(),
        onDeleteCredential: vi.fn(),
        onSetActive: vi.fn(),
        onTestConnection: vi.fn(),
        onDeleteProfile: vi.fn(),
      },
    });

    // Verify it renders Max tokens in candidate purpose
    expect(wrapper.text()).toContain("Max tokens");
    expect(wrapper.text()).toContain("2048");

    // Verify it does NOT render Test connection button
    expect(wrapper.find(".actions").html()).not.toContain("Test connection");
  });

  it("renders key input initially empty with password style and correct autocomplete", () => {
    const profile = createCandidateProfile();
    const wrapper = mount(ModelProfileCard, {
      props: {
        profile,
        active: false,
        runtime: { state: "idle", credentialExists: true },
        clearEpoch: 1,
        onSaveCredential: vi.fn(),
        onDeleteCredential: vi.fn(),
        onSetActive: vi.fn(),
        onTestConnection: vi.fn(),
        onDeleteProfile: vi.fn(),
      },
    });

    const input = wrapper.find("input[placeholder='Enter a new API Key']");
    expect(input.exists()).toBe(true);
    expect((input.element as HTMLInputElement).value).toBe("");
    expect(input.attributes("type")).toBe("password");
    expect(input.attributes("autocomplete")).toBe("new-password");
  });

  it("clears input on save success", async () => {
    const onSaveCredential = vi.fn().mockResolvedValue(true);
    const wrapper = mount(ModelProfileCard, {
      props: {
        profile: createCandidateProfile(),
        active: false,
        runtime: { state: "idle", credentialExists: false },
        clearEpoch: 1,
        onSaveCredential,
        onDeleteCredential: vi.fn(),
        onSetActive: vi.fn(),
        onTestConnection: vi.fn(),
        onDeleteProfile: vi.fn(),
      },
    });

    const input = wrapper.find("input[placeholder='Enter a new API Key']");
    await input.setValue("new-secret-key");
    await wrapper.findAll("button").find(b => b.text().includes("Save / replace"))!.trigger("click");

    expect(onSaveCredential).toHaveBeenCalledWith("candidate-prof", "new-secret-key");
    expect((input.element as HTMLInputElement).value).toBe("");
  });

  it("does not clear input on save failure", async () => {
    const onSaveCredential = vi.fn().mockResolvedValue(false);
    const wrapper = mount(ModelProfileCard, {
      props: {
        profile: createCandidateProfile(),
        active: false,
        runtime: { state: "idle", credentialExists: false },
        clearEpoch: 1,
        onSaveCredential,
        onDeleteCredential: vi.fn(),
        onSetActive: vi.fn(),
        onTestConnection: vi.fn(),
        onDeleteProfile: vi.fn(),
      },
    });

    const input = wrapper.find("input[placeholder='Enter a new API Key']");
    await input.setValue("new-secret-key");
    await wrapper.findAll("button").find(b => b.text().includes("Save / replace"))!.trigger("click");

    expect((input.element as HTMLInputElement).value).toBe("new-secret-key");
  });

  it("clears input on delete success and stops if cancelled", async () => {
    const onDeleteCredential = vi.fn().mockResolvedValue(true);
    const wrapper = mount(ModelProfileCard, {
      props: {
        profile: createCandidateProfile(),
        active: false,
        runtime: { state: "idle", credentialExists: true },
        clearEpoch: 1,
        onSaveCredential: vi.fn(),
        onDeleteCredential,
        onSetActive: vi.fn(),
        onTestConnection: vi.fn(),
        onDeleteProfile: vi.fn(),
      },
    });

    const input = wrapper.find("input[placeholder='Enter a new API Key']");
    await input.setValue("old-garbage");

    // Mock cancel
    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(false);
    await wrapper.findAll("button").find(b => b.text().includes("Delete API Key"))!.trigger("click");
    expect(onDeleteCredential).not.toHaveBeenCalled();
    expect((input.element as HTMLInputElement).value).toBe("old-garbage");

    // Mock confirm
    confirmSpy.mockReturnValue(true);
    await wrapper.findAll("button").find(b => b.text().includes("Delete API Key"))!.trigger("click");
    expect(onDeleteCredential).toHaveBeenCalledWith("candidate-prof");
    expect((input.element as HTMLInputElement).value).toBe("");

    confirmSpy.mockRestore();
  });

  it("does not clear input on delete failure", async () => {
    const onDeleteCredential = vi.fn().mockResolvedValue(false);
    const wrapper = mount(ModelProfileCard, {
      props: {
        profile: createCandidateProfile(),
        active: false,
        runtime: { state: "idle", credentialExists: true },
        clearEpoch: 1,
        onSaveCredential: vi.fn(),
        onDeleteCredential,
        onSetActive: vi.fn(),
        onTestConnection: vi.fn(),
        onDeleteProfile: vi.fn(),
      },
    });

    const input = wrapper.find("input[placeholder='Enter a new API Key']");
    await input.setValue("old-garbage");

    const confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
    await wrapper.findAll("button").find(b => b.text().includes("Delete API Key"))!.trigger("click");

    expect(onDeleteCredential).toHaveBeenCalledWith("candidate-prof");
    expect((input.element as HTMLInputElement).value).toBe("old-garbage");

    confirmSpy.mockRestore();
  });

  it("clears input when clearEpoch changes", async () => {
    const wrapper = mount(ModelProfileCard, {
      props: {
        profile: createCandidateProfile(),
        active: false,
        runtime: { state: "idle", credentialExists: false },
        clearEpoch: 1,
        onSaveCredential: vi.fn(),
        onDeleteCredential: vi.fn(),
        onSetActive: vi.fn(),
        onTestConnection: vi.fn(),
        onDeleteProfile: vi.fn(),
      },
    });

    const input = wrapper.find("input[placeholder='Enter a new API Key']");
    await input.setValue("temp-key");

    await wrapper.setProps({ clearEpoch: 2 });
    expect((input.element as HTMLInputElement).value).toBe("");
  });

  it("displays card error appropriately, specifically for CREDENTIAL_DELETE_REQUIRED", () => {
    const wrapper = mount(ModelProfileCard, {
      props: {
        profile: createCandidateProfile(),
        active: false,
        runtime: {
          state: "idle",
          credentialExists: true,
          error: {
            code: "CREDENTIAL_DELETE_REQUIRED",
            safeMessage: "Please delete the API Key before deleting this profile.",
            operation: "deleteProfile",
            recoverable: false
          }
        },
        clearEpoch: 1,
        onSaveCredential: vi.fn(),
        onDeleteCredential: vi.fn(),
        onSetActive: vi.fn(),
        onTestConnection: vi.fn(),
        onDeleteProfile: vi.fn(),
      },
    });

    const errorSection = wrapper.find(".card-error");
    expect(errorSection.exists()).toBe(true);
    expect(errorSection.text()).toContain("CREDENTIAL_DELETE_REQUIRED");
    expect(errorSection.text()).toContain("Please delete the API Key before deleting this profile.");
  });
});

describe("ModelProfileForm component", () => {
  it("uses purpose = candidate_extraction and fixed temperature = 0.0", () => {
    const wrapper = mount(ModelProfileForm, {
      props: {
        purpose: "candidate_extraction",
        profile: undefined,
        saving: false,
        errorMessage: undefined,
      },
    });

    expect(wrapper.text()).toContain("candidate extraction profile");
    // Verify temperature input is disabled and value is 0.0
    const tempLabel = wrapper.findAll("label").find(l => l.text().includes("Temperature"));
    expect(tempLabel).toBeDefined();
    const tempInput = tempLabel?.find("input");
    expect(tempInput?.attributes("disabled")).toBeDefined();
    expect((tempInput?.element as HTMLInputElement).value).toBe("0.0");

    // Verify embedding dimension is not rendered
    expect(wrapper.text()).not.toContain("Embedding dimension");
  });

  it("validates max tokens with 1..=4096 constraints", async () => {
    const wrapper = mount(ModelProfileForm, {
      props: {
        purpose: "candidate_extraction",
        profile: undefined,
        saving: false,
        errorMessage: undefined,
      },
    });

    const displayNameInput = wrapper.findAll("input")[0];
    const baseUrlInput = wrapper.findAll("input")[1];
    const modelNameInput = wrapper.findAll("input")[2];
    const maxTokensInput = wrapper.findAll("input")[4];

    await displayNameInput.setValue("Candidate");
    await baseUrlInput.setValue("https://candidate.example/v1");
    await modelNameInput.setValue("candidate-model");

    // Set maxTokens to 0 (invalid)
    await maxTokensInput.setValue(0);
    expect(wrapper.find(".primary").attributes("disabled")).toBeDefined();

    // Set maxTokens to 4097 (invalid)
    await maxTokensInput.setValue(4097);
    expect(wrapper.find(".primary").attributes("disabled")).toBeDefined();

    // Set maxTokens to 2048 (valid)
    await maxTokensInput.setValue(2048);
    expect(wrapper.find(".primary").attributes("disabled")).toBeUndefined();
  });
});
