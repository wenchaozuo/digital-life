import { invoke } from "@tauri-apps/api/core";
import type { LifeIdentity } from "../life";
import type { PersonaTemplate } from "../persona";

export interface StoredPersonaTemplate {
  id: string;
  name: string;
  version: number;
  personaJson: string;
}

export interface StorageLocationInfo {
  currentDirectory: string;
  isDefaultDirectory: boolean;
}

export interface StorageLocationValidation {
  currentDirectory: string;
  candidateDirectory: string;
  isValid: boolean;
  errorCode?: string;
  errorMessage?: string;
}

export interface StorageMigrationResult {
  success: boolean;
  oldDirectory: string;
  newDirectory: string;
  restartRequired: boolean;
  originalDatabaseRetained: boolean;
  failedStage?: string;
  errorCode?: string;
  errorMessage?: string;
}

export class StorageService {
  async initialize(): Promise<void> {
    await invoke("initialize_storage");
  }

  async getStorageLocation(): Promise<StorageLocationInfo> {
    return invoke<StorageLocationInfo>("get_storage_location");
  }

  async validateStorageLocation(
    candidateDirectory: string,
  ): Promise<StorageLocationValidation> {
    return invoke<StorageLocationValidation>("validate_storage_location", {
      candidateDirectory,
    });
  }

  async migrateStorageLocation(
    candidateDirectory: string,
  ): Promise<StorageMigrationResult> {
    return invoke<StorageMigrationResult>("migrate_storage_location", {
      candidateDirectory,
    });
  }

  async saveLife(identity: LifeIdentity): Promise<void> {
    await invoke("save_life_identity", { identity });
  }

  async getCurrentLife(): Promise<LifeIdentity | undefined> {
    const life = await invoke<LifeIdentity | null>("get_current_life_identity");
    return life ?? undefined;
  }

  async getLife(id: string): Promise<LifeIdentity | undefined> {
    const life = await invoke<LifeIdentity | null>("get_life_identity", { id });
    return life ?? undefined;
  }

  async updateLifeBaseInfo(
    id: string,
    name: string,
    bodyId: string,
  ): Promise<LifeIdentity> {
    return invoke<LifeIdentity>("update_life_identity_base_info", {
      id,
      name,
      bodyId,
    });
  }

  async savePersona(persona: PersonaTemplate): Promise<void> {
    const storedPersona: StoredPersonaTemplate = {
      id: persona.id,
      name: persona.name,
      version: persona.version,
      personaJson: JSON.stringify(persona),
    };

    await invoke("save_persona_template", { persona: storedPersona });
  }

  async getPersona(id: string): Promise<StoredPersonaTemplate | undefined> {
    const storedPersona = await invoke<StoredPersonaTemplate | null>(
      "get_persona_template",
      { id },
    );

    if (!storedPersona) {
      return undefined;
    }

    return storedPersona;
  }
}

export const storageService = new StorageService();
