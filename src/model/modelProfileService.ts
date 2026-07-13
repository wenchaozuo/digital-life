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
  temperature: number | null;
  maxTokens: number | null;
  embeddingDimension: number | null;
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
    | "DATABASE_ERROR";
  message: string;
  recoverable: boolean;
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
}

export const modelProfileService = new ModelProfileService();
