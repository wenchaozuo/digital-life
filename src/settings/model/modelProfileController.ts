import {
  modelProfileService,
  type ActiveModelProfile,
  type CreateModelProfileRequest,
  type ModelConnectionTestResult,
  type ModelProfile,
  type ModelPurpose,
  type UpdateModelProfileRequest,
} from "../../model/modelProfileService.ts";
import {
  credentialService,
  type ICredentialService,
} from "./credentialService.ts";

export type ModelSettingsState =
  | "idle"
  | "loading"
  | "editing"
  | "savingProfile"
  | "savingCredential"
  | "deletingCredential"
  | "settingActive"
  | "testingConnection"
  | "deletingProfile"
  | "succeeded"
  | "failed";

export type ModelSettingsOperation =
  | "load"
  | "saveProfile"
  | "saveCredential"
  | "deleteCredential"
  | "setActive"
  | "testConnection"
  | "deleteProfile";

export interface ModelSettingsError {
  code: string;
  message: string;
  operation: ModelSettingsOperation;
}

export interface ProfileCardRuntimeState {
  state: ModelSettingsState;
  credentialExists: boolean;
  error?: ModelSettingsError;
  connectionTest?: ModelConnectionTestResult;
}

export interface ChatProfileDraft {
  purpose: "chat";
  displayName: string;
  baseUrl: string;
  modelName: string;
  temperature: number;
  maxTokens: number;
}

export interface EmbeddingProfileDraft {
  purpose: "embedding";
  displayName: string;
  baseUrl: string;
  modelName: string;
  embeddingDimension: number;
}

export type ModelProfileDraft = ChatProfileDraft | EmbeddingProfileDraft;

export interface IModelProfileService {
  create(request: CreateModelProfileRequest): Promise<ModelProfile>;
  update(request: UpdateModelProfileRequest): Promise<ModelProfile>;
  list(purpose: ModelPurpose | null): Promise<ModelProfile[]>;
  delete(profileId: string): Promise<{ profileId: string; deleted: boolean }>;
  setActive(purpose: ModelPurpose, profileId: string): Promise<ActiveModelProfile>;
  getActive(purpose: ModelPurpose): Promise<ActiveModelProfile | null>;
  testConnection(request: {
    profileId: string;
    purpose: ModelPurpose;
  }): Promise<ModelConnectionTestResult>;
}

export class ModelProfileController {
  readonly purpose: ModelPurpose;
  profiles: ModelProfile[] = [];
  activeProfile: ActiveModelProfile | null = null;
  listState: ModelSettingsState = "idle";
  listError?: ModelSettingsError;
  formState: ModelSettingsState = "idle";
  formError?: ModelSettingsError;
  cardStates: Record<string, ProfileCardRuntimeState> = {};

  private readonly profilesService: IModelProfileService;
  private readonly credentials: ICredentialService;

  constructor(
    purpose: ModelPurpose,
    profilesService: IModelProfileService = modelProfileService,
    credentials: ICredentialService = credentialService,
  ) {
    this.purpose = purpose;
    this.profilesService = profilesService;
    this.credentials = credentials;
  }

  async refresh(): Promise<void> {
    this.listState = "loading";
    this.listError = undefined;
    try {
      const [profiles, activeProfile] = await Promise.all([
        this.profilesService.list(this.purpose),
        this.profilesService.getActive(this.purpose),
      ]);
      this.profiles = profiles;
      this.activeProfile = activeProfile;
      const nextStates: Record<string, ProfileCardRuntimeState> = {};
      await Promise.all(
        profiles.map(async (profile) => {
          const prior = this.cardStates[profile.id];
          try {
            const credential = await this.credentials.has(this.purpose, profile.id);
            nextStates[profile.id] = {
              state: prior?.state === "testingConnection" ? "testingConnection" : "idle",
              credentialExists: credential.exists,
              connectionTest: prior?.connectionTest,
            };
          } catch (caught: unknown) {
            nextStates[profile.id] = {
              state: "failed",
              credentialExists: false,
              connectionTest: prior?.connectionTest,
              error: errorFromUnknown(caught, "load"),
            };
          }
        }),
      );
      this.cardStates = nextStates;
      this.listState = "succeeded";
    } catch (caught: unknown) {
      this.listState = "failed";
      this.listError = errorFromUnknown(caught, "load");
    }
  }

  async saveProfile(
    draft: ModelProfileDraft,
    profileId?: string,
  ): Promise<ModelProfile | undefined> {
    if (draft.purpose !== this.purpose || !isDraftValid(draft)) {
      this.formState = "failed";
      this.formError = {
        code: "INVALID_PROFILE_FORM",
        message: "Complete the required model profile fields before saving.",
        operation: "saveProfile",
      };
      return undefined;
    }
    this.formState = "savingProfile";
    this.formError = undefined;
    this.setCardState(profileId, "savingProfile");
    try {
      const profile = profileId
        ? await this.profilesService.update(updateRequest(profileId, draft))
        : await this.profilesService.create(createRequest(draft));
      this.formState = "succeeded";
      await this.refresh();
      return profile;
    } catch (caught: unknown) {
      const error = errorFromUnknown(caught, "saveProfile");
      this.formState = "failed";
      this.formError = error;
      this.setCardError(profileId, error);
      return undefined;
    }
  }

  async saveCredential(profileId: string, apiKey: string): Promise<boolean> {
    if (apiKey.trim().length === 0) {
      this.setCardError(profileId, {
        code: "API_KEY_REQUIRED",
        message: "Enter an API Key before saving.",
        operation: "saveCredential",
      });
      return false;
    }
    this.setCardState(profileId, "savingCredential");
    try {
      await this.credentials.save(this.purpose, profileId, apiKey);
      const status = await this.credentials.has(this.purpose, profileId);
      this.setCardState(profileId, "succeeded", status.exists);
      return true;
    } catch (caught: unknown) {
      this.setCardError(profileId, errorFromUnknown(caught, "saveCredential"));
      return false;
    }
  }

  async deleteCredential(profileId: string): Promise<boolean> {
    this.setCardState(profileId, "deletingCredential");
    try {
      await this.credentials.delete(this.purpose, profileId);
      const status = await this.credentials.has(this.purpose, profileId);
      this.setCardState(profileId, "succeeded", status.exists);
      return true;
    } catch (caught: unknown) {
      this.setCardError(profileId, errorFromUnknown(caught, "deleteCredential"));
      return false;
    }
  }

  async setActive(profileId: string): Promise<boolean> {
    this.setCardState(profileId, "settingActive");
    try {
      await this.profilesService.setActive(this.purpose, profileId);
      this.activeProfile = await this.profilesService.getActive(this.purpose);
      this.setCardState(profileId, "succeeded");
      return true;
    } catch (caught: unknown) {
      this.setCardError(profileId, errorFromUnknown(caught, "setActive"));
      return false;
    }
  }

  async testConnection(profileId: string): Promise<ModelConnectionTestResult | undefined> {
    const state = this.cardState(profileId);
    if (!state.credentialExists) {
      this.setCardError(profileId, {
        code: "CREDENTIAL_REQUIRED",
        message: "Save an API Key before testing this profile.",
        operation: "testConnection",
      });
      return undefined;
    }
    this.setCardState(profileId, "testingConnection");
    try {
      const result = await this.profilesService.testConnection({
        profileId,
        purpose: this.purpose,
      });
      const error = result.success
        ? undefined
        : {
            code: result.errorCode ?? "CONNECTION_TEST_FAILED",
            message: result.errorMessage ?? "The connection test did not succeed.",
            operation: "testConnection" as const,
          };
      this.cardStates[profileId] = {
        state: result.success ? "succeeded" : "failed",
        credentialExists: state.credentialExists,
        connectionTest: result,
        error,
      };
      return result;
    } catch (caught: unknown) {
      this.setCardError(profileId, errorFromUnknown(caught, "testConnection"));
      return undefined;
    }
  }

  async deleteProfile(profileId: string): Promise<boolean> {
    this.setCardState(profileId, "deletingProfile");
    try {
      const credential = await this.credentials.has(this.purpose, profileId);
      if (credential.exists) {
        this.setCardError(profileId, {
          code: "CREDENTIAL_EXISTS",
          message: "Delete this profile's API Key before deleting the profile.",
          operation: "deleteProfile",
        });
        return false;
      }
      await this.profilesService.delete(profileId);
      await this.refresh();
      return true;
    } catch (caught: unknown) {
      this.setCardError(profileId, errorFromUnknown(caught, "deleteProfile"));
      return false;
    }
  }

  cardState(profileId: string): ProfileCardRuntimeState {
    return this.cardStates[profileId] ?? {
      state: "idle",
      credentialExists: false,
    };
  }

  private setCardState(
    profileId: string | undefined,
    state: ModelSettingsState,
    credentialExists?: boolean,
  ): void {
    if (!profileId) {
      return;
    }
    const previous = this.cardState(profileId);
    this.cardStates[profileId] = {
      ...previous,
      state,
      credentialExists: credentialExists ?? previous.credentialExists,
      error: undefined,
    };
  }

  private setCardError(profileId: string | undefined, error: ModelSettingsError): void {
    if (!profileId) {
      return;
    }
    const previous = this.cardState(profileId);
    this.cardStates[profileId] = {
      ...previous,
      state: "failed",
      error,
    };
  }
}

function createRequest(draft: ModelProfileDraft): CreateModelProfileRequest {
  const base = {
    purpose: draft.purpose,
    providerKind: "openai_compatible" as const,
    displayName: draft.displayName.trim(),
    baseUrl: draft.baseUrl.trim(),
    modelName: draft.modelName.trim(),
  };
  return draft.purpose === "chat"
    ? { ...base, temperature: draft.temperature, maxTokens: draft.maxTokens }
    : { ...base, embeddingDimension: draft.embeddingDimension };
}

function updateRequest(
  profileId: string,
  draft: ModelProfileDraft,
): UpdateModelProfileRequest {
  return { profileId, ...createRequest(draft) };
}

export function isDraftValid(draft: ModelProfileDraft): boolean {
  if (
    draft.displayName.trim().length === 0 ||
    draft.baseUrl.trim().length === 0 ||
    draft.modelName.trim().length === 0 ||
    !/^https?:\/\//i.test(draft.baseUrl.trim())
  ) {
    return false;
  }
  return draft.purpose === "chat"
    ? Number.isFinite(draft.temperature) &&
        draft.temperature >= 0 &&
        draft.temperature <= 2 &&
        Number.isInteger(draft.maxTokens) &&
        draft.maxTokens > 0
    : Number.isInteger(draft.embeddingDimension) &&
        draft.embeddingDimension > 0;
}

export function errorFromUnknown(
  caught: unknown,
  operation: ModelSettingsOperation,
): ModelSettingsError {
  const credentialOperation =
    operation === "saveCredential" || operation === "deleteCredential";
  if (isErrorRecord(caught)) {
    return {
      code: typeof caught.code === "string" ? caught.code : "MODEL_SETTINGS_ERROR",
      message:
        !credentialOperation && typeof caught.message === "string"
          ? caught.message
          : credentialOperation
            ? "The credential operation could not be completed."
            : "The model settings operation could not be completed.",
      operation,
    };
  }
  return {
    code: "MODEL_SETTINGS_ERROR",
    message: credentialOperation
      ? "The credential operation could not be completed."
      : "The model settings operation could not be completed.",
    operation,
  };
}

function isErrorRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
