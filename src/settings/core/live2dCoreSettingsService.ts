import { invoke } from "@tauri-apps/api/core";

import type {
  ManagedCubismCoreSnapshot,
  ManagedCubismCoreStatus,
} from "../../body/managedCubismCore.ts";

export type { ManagedCubismCoreSnapshot, ManagedCubismCoreStatus } from "../../body/managedCubismCore.ts";

export const LIVE2D_CORE_SCRIPT_FILENAME = "live2dcubismcore.min.js";

export interface Live2DCoreSettingsError {
  readonly code: string;
  readonly message: string;
}

const CORE_ERROR_MESSAGES: Record<string, string> = {
  LIVE2D_CORE_UNAPPROVED: "The selected file is not an approved Cubism Core.",
  LIVE2D_CORE_INVALID_INPUT: "Select the exact live2dcubismcore.min.js file.",
  LIVE2D_CORE_TOO_LARGE: "The selected Cubism Core file is too large.",
  LIVE2D_CORE_UNSAFE_PATH: "The selected Cubism Core path is not safe.",
  LIVE2D_CORE_IMPORT_COPY_FAILED: "The Cubism Core could not be installed safely.",
  LIVE2D_CORE_IMPORT_VERIFY_FAILED: "The installed Cubism Core failed verification.",
  LIVE2D_CORE_REGISTRATION_FAILED: "The Cubism Core could not be registered.",
  LIVE2D_CORE_ROLLBACK_FAILED: "The previous Cubism Core could not be preserved.",
  LIVE2D_CORE_CORRUPT: "The installed Cubism Core is corrupt or unavailable.",
  LIVE2D_CORE_FILE_MISSING: "The selected Cubism Core file is unavailable.",
  LIVE2D_CORE_DATABASE_UNAVAILABLE: "The local Cubism Core authority is unavailable.",
  LIVE2D_CORE_COMPONENT_NOT_REGISTERED: "No Cubism Core is currently installed.",
  LIVE2D_CORE_IMPORT_FAILED: "The Cubism Core installation could not be completed.",
};

export function isExactLive2DCoreFilePath(value: string): boolean {
  const filename = value.split(/[\\/]/).pop();
  return filename === LIVE2D_CORE_SCRIPT_FILENAME;
}

export function coreSettingsErrorFromUnknown(
  caught: unknown,
): Live2DCoreSettingsError {
  if (typeof caught === "object" && caught !== null) {
    const candidate = caught as { code?: unknown };
    if (
      typeof candidate.code === "string" &&
      CORE_ERROR_MESSAGES[candidate.code] !== undefined
    ) {
      return {
        code: candidate.code,
        message: CORE_ERROR_MESSAGES[candidate.code],
      };
    }
  }
  return {
    code: "LIVE2D_CORE_IMPORT_FAILED",
    message: CORE_ERROR_MESSAGES.LIVE2D_CORE_IMPORT_FAILED,
  };
}

export class Live2DCoreSettingsService {
  async getSnapshot(): Promise<ManagedCubismCoreSnapshot> {
    return invoke<ManagedCubismCoreSnapshot>("get_cubism_core_snapshot");
  }

  async install(sourcePath: string): Promise<ManagedCubismCoreSnapshot> {
    return invoke<ManagedCubismCoreSnapshot>("import_cubism_core", {
      request: { sourcePath },
    });
  }
}

export const live2dCoreSettingsService = new Live2DCoreSettingsService();

export function coreStatusLabel(
  status: ManagedCubismCoreStatus | undefined,
): string {
  switch (status) {
    case "ready-for-startup":
      return "Ready for startup";
    case "corrupt-unavailable":
      return "Corrupt / unavailable";
    case "restart-required":
      return "Restart required";
    case "not-configured":
      return "Not configured";
    default:
      return "Loading…";
  }
}
