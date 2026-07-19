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
