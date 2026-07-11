import type {
  StorageLocationValidation,
  StorageMigrationResult,
} from "../storage";

export type StorageSettingsPhase =
  | "unselected"
  | "selected"
  | "validating"
  | "validated"
  | "validationFailed"
  | "awaitingConfirmation"
  | "migrating"
  | "migrationSucceeded"
  | "migrationFailed";

export interface StorageSettingsError {
  code: string;
  message: string;
  failedStage?: string;
}

export function isDirectorySelectionCancelled(
  selection: string | null,
): selection is null {
  return selection === null;
}

export function canStartMigration(
  phase: StorageSettingsPhase,
  candidateDirectory: string,
): boolean {
  return phase === "validated" && candidateDirectory.trim().length > 0;
}

export function canInteractWithLocation(phase: StorageSettingsPhase): boolean {
  return phase !== "migrating";
}

export function errorFromValidation(
  result: StorageLocationValidation,
): StorageSettingsError | undefined {
  if (result.isValid) {
    return undefined;
  }

  return {
    code: result.errorCode ?? "STORAGE_LOCATION_INVALID",
    message: result.errorMessage ?? "The selected directory could not be validated.",
  };
}

export function errorFromMigration(
  result: StorageMigrationResult,
): StorageSettingsError | undefined {
  if (result.success) {
    return undefined;
  }

  return {
    code: result.errorCode ?? "STORAGE_MIGRATION_FAILED",
    message: result.errorMessage ?? "The storage migration did not complete.",
    failedStage: result.failedStage,
  };
}

export function errorFromUnknown(error: unknown): StorageSettingsError {
  if (error instanceof Error) {
    return { code: "TAURI_COMMAND_ERROR", message: error.message };
  }

  if (typeof error === "string") {
    return { code: "TAURI_COMMAND_ERROR", message: error };
  }

  return {
    code: "TAURI_COMMAND_ERROR",
    message: "The operation could not be completed. The original database remains available.",
  };
}
