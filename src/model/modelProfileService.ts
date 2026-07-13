import { invoke } from "@tauri-apps/api/core";

export type ModelPurpose = "chat" | "embedding";
export type ModelProviderKind = "openai_compatible";

export interface ModelProfile {
  id: string;
  purpose: ModelPurpose;
  providerKind: ModelProviderKind;
  displayName: string;
  baseUrl: string;
  modelName: string;
  temperature: number | null;
  maxTokens: number | null;
  embeddingDimension: number | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateModelProfileRequest {
  purpose: ModelPurpose;
  providerKind: ModelProviderKind;
  displayName: string;
  baseUrl: string;
  modelName: string;
  temperature?: number;
  maxTokens?: number;
  embeddingDimension?: number;
}

export interface UpdateModelProfileRequest
  extends CreateModelProfileRequest {
  profileId: string;
}

export interface ActiveModelProfile {
  purpose: ModelPurpose;
  profileId: string;
}

export interface DeleteModelProfileResult {
  profileId: string;
  deleted: boolean;
  activeMappingCleared: boolean;
}

export interface ModelProfileError {
  code:
    | "INVALID_REQUEST"
    | "INVALID_BASE_URL"
    | "INVALID_PARAMETERS"
    | "PROFILE_NOT_FOUND"
    | "PURPOSE_MISMATCH"
    | "UNSUPPORTED_PROVIDER"
    | "DATABASE_ERROR";
  message: string;
  recoverable: boolean;
}

export type ModelRuntimeErrorCode =
  | "NO_ACTIVE_PROFILE"
  | "PROFILE_NOT_FOUND"
  | "PROFILE_PURPOSE_MISMATCH"
  | "CREDENTIAL_NOT_FOUND"
  | "UNSUPPORTED_PROVIDER"
  | "INVALID_PROFILE"
  | "PROVIDER_INITIALIZATION_FAILED"
  | "AUTHENTICATION_FAILED"
  | "RATE_LIMITED"
  | "NETWORK_UNAVAILABLE"
  | "REQUEST_TIMEOUT"
  | "INVALID_PROVIDER_RESPONSE"
  | "DIMENSION_MISMATCH"
  | "CONNECTION_TEST_FAILED"
  | "CONNECTION_TEST_IN_PROGRESS";

export interface ModelConnectionTestRequest {
  profileId: string;
  purpose: ModelPurpose;
}

export interface ModelConnectionTestResult {
  profileId: string;
  purpose: ModelPurpose;
  success: boolean;
  providerKind: ModelProviderKind | null;
  modelName: string | null;
  latencyMs: number;
  embeddingDimension: number | null;
  errorCode: ModelRuntimeErrorCode | null;
  errorMessage: string | null;
}

export class ModelProfileService {
  async create(request: CreateModelProfileRequest): Promise<ModelProfile> {
    return invoke<ModelProfile>("create_model_profile", { request });
  }

  async list(purpose: ModelPurpose | null = null): Promise<ModelProfile[]> {
    return invoke<ModelProfile[]>("list_model_profiles", {
      request: { purpose },
    });
  }

  async get(profileId: string): Promise<ModelProfile> {
    return invoke<ModelProfile>("get_model_profile", { profileId });
  }

  async update(request: UpdateModelProfileRequest): Promise<ModelProfile> {
    return invoke<ModelProfile>("update_model_profile", { request });
  }

  async delete(profileId: string): Promise<DeleteModelProfileResult> {
    return invoke<DeleteModelProfileResult>("delete_model_profile", {
      profileId,
    });
  }

  async setActive(
    purpose: ModelPurpose,
    profileId: string,
  ): Promise<ActiveModelProfile> {
    return invoke<ActiveModelProfile>("set_active_model_profile", {
      request: { purpose, profileId },
    });
  }

  async getActive(
    purpose: ModelPurpose,
  ): Promise<ActiveModelProfile | null> {
    return invoke<ActiveModelProfile | null>("get_active_model_profile", {
      purpose,
    });
  }

  async testConnection(
    request: ModelConnectionTestRequest,
  ): Promise<ModelConnectionTestResult> {
    return invoke<ModelConnectionTestResult>("test_model_profile_connection", {
      request,
    });
  }
}

export const modelProfileService = new ModelProfileService();
