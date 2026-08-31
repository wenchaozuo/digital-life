import { invoke } from "@tauri-apps/api/core";
import type { ModelPurpose } from "../../model/modelProfileService.ts";

export type CredentialPurpose =
  | "CHAT_MODEL_API_KEY"
  | "EMBEDDING_MODEL_API_KEY"
  | "CANDIDATE_EXTRACTION_MODEL_API_KEY"
  | "VISION_MODEL_API_KEY";

export interface CredentialStatus {
  purpose: CredentialPurpose;
  profileId: string;
  exists: boolean;
}

export interface SaveCredentialResponse extends CredentialStatus {
  updated: boolean;
}

export interface DeleteCredentialResponse extends CredentialStatus {
  deleted: boolean;
}

export interface ICredentialService {
  save(
    purpose: ModelPurpose,
    profileId: string,
    apiKey: string,
  ): Promise<SaveCredentialResponse>;
  has(purpose: ModelPurpose, profileId: string): Promise<CredentialStatus>;
  delete(
    purpose: ModelPurpose,
    profileId: string,
  ): Promise<DeleteCredentialResponse>;
}

export function credentialPurposeFor(
  purpose: ModelPurpose,
): CredentialPurpose {
  if (purpose === "chat") {
    return "CHAT_MODEL_API_KEY";
  } else if (purpose === "embedding") {
    return "EMBEDDING_MODEL_API_KEY";
  } else if (purpose === "candidate_extraction") {
    return "CANDIDATE_EXTRACTION_MODEL_API_KEY";
  } else {
    return "VISION_MODEL_API_KEY";
  }
}

export class CredentialService implements ICredentialService {
  async save(
    purpose: ModelPurpose,
    profileId: string,
    apiKey: string,
  ): Promise<SaveCredentialResponse> {
    return invoke<SaveCredentialResponse>("save_api_credential", {
      request: {
        purpose: credentialPurposeFor(purpose),
        profileId,
        apiKey,
      },
    });
  }

  async has(purpose: ModelPurpose, profileId: string): Promise<CredentialStatus> {
    return invoke<CredentialStatus>("has_api_credential", {
      request: {
        purpose: credentialPurposeFor(purpose),
        profileId,
      },
    });
  }

  async delete(
    purpose: ModelPurpose,
    profileId: string,
  ): Promise<DeleteCredentialResponse> {
    return invoke<DeleteCredentialResponse>("delete_api_credential", {
      request: {
        purpose: credentialPurposeFor(purpose),
        profileId,
      },
    });
  }
}

export const credentialService = new CredentialService();
