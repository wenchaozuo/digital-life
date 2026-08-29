import { invoke } from "@tauri-apps/api/core";

export interface ScreenPerceptionPolicy {
  lifeId: string;
  enabled: boolean;
  revision: number;
  createdAt: string;
  updatedAt: string;
}

export type ScreenPerceptionSessionStatus =
  | { status: "disarmed" }
  | { status: "armed"; lifeId: string };

export interface ScreenPerceptionSettingsError {
  readonly code: string;
  readonly message: string;
  readonly recoverable: boolean;
}

interface ScreenPerceptionLifeRequest {
  lifeId: string;
}

const SCREEN_PERCEPTION_ERROR_MESSAGES: Record<string, string> = {
  SCREEN_PERCEPTION_INVALID_ARGUMENT:
    "The screen perception request is invalid.",
  SCREEN_PERCEPTION_LIFE_NOT_FOUND: "The selected Life could not be found.",
  SCREEN_PERCEPTION_POLICY_NOT_FOUND:
    "No screen perception consent has been configured for this Life.",
  SCREEN_PERCEPTION_POLICY_DISABLED:
    "Screen perception consent is disabled for this Life.",
  SCREEN_PERCEPTION_POLICY_CONFLICT:
    "The screen perception consent changed before it was created.",
  SCREEN_PERCEPTION_POLICY_EVENT_CONFLICT:
    "This screen perception consent action conflicts with an existing action.",
  SCREEN_PERCEPTION_REVISION_CONFLICT:
    "Screen perception consent changed elsewhere. Refresh and try again.",
  SCREEN_PERCEPTION_INVALID_TRANSITION:
    "The screen perception consent is already in that state.",
  SCREEN_PERCEPTION_SESSION_NOT_ARMED:
    "Screen perception is not enabled for this application session.",
  SCREEN_PERCEPTION_SESSION_LIFE_MISMATCH:
    "Screen perception is enabled for a different Life in this session.",
  SCREEN_PERCEPTION_DATABASE_UNAVAILABLE:
    "Screen perception settings are temporarily unavailable. Try again.",
};

function freshEventId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
    throw new Error("Secure event identity generation is unavailable.");
  }

  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0"));
  return [
    hex.slice(0, 4).join(""),
    hex.slice(4, 6).join(""),
    hex.slice(6, 8).join(""),
    hex.slice(8, 10).join(""),
    hex.slice(10, 16).join(""),
  ].join("-");
}

export function screenPerceptionErrorFromUnknown(
  caught: unknown,
): ScreenPerceptionSettingsError {
  if (typeof caught === "object" && caught !== null) {
    const candidate = caught as { code?: unknown; recoverable?: unknown };
    if (typeof candidate.code === "string") {
      const safeMessage = SCREEN_PERCEPTION_ERROR_MESSAGES[candidate.code];
      if (safeMessage !== undefined) {
        return {
          code: candidate.code,
          message: safeMessage,
          recoverable:
            typeof candidate.recoverable === "boolean"
              ? candidate.recoverable
              : true,
        };
      }
    }
  }

  return {
    code: "SCREEN_PERCEPTION_SETTINGS_UNAVAILABLE",
    message: "Screen perception settings could not be updated. Try again.",
    recoverable: true,
  };
}

export class ScreenPerceptionSettingsService {
  async getPolicy(lifeId: string): Promise<ScreenPerceptionPolicy | null> {
    return invoke<ScreenPerceptionPolicy | null>(
      "get_screen_perception_policy",
      { request: { lifeId } satisfies ScreenPerceptionLifeRequest },
    );
  }

  async createPolicy(
    lifeId: string,
    enabled: boolean,
  ): Promise<ScreenPerceptionPolicy> {
    return invoke<ScreenPerceptionPolicy>("create_screen_perception_policy", {
      request: { lifeId, enabled },
    });
  }

  async updatePolicy(
    lifeId: string,
    enabled: boolean,
    expectedRevision: number,
  ): Promise<ScreenPerceptionPolicy> {
    return invoke<ScreenPerceptionPolicy>("update_screen_perception_policy", {
      request: {
        eventId: freshEventId(),
        lifeId,
        enabled,
        expectedRevision,
      },
    });
  }

  async getSessionStatus(): Promise<ScreenPerceptionSessionStatus> {
    return invoke<ScreenPerceptionSessionStatus>(
      "get_screen_perception_session_status",
    );
  }

  async armSession(lifeId: string): Promise<ScreenPerceptionSessionStatus> {
    return invoke<ScreenPerceptionSessionStatus>(
      "arm_screen_perception_session",
      { request: { lifeId } satisfies ScreenPerceptionLifeRequest },
    );
  }

  async disarmSession(): Promise<ScreenPerceptionSessionStatus> {
    return invoke<ScreenPerceptionSessionStatus>(
      "disarm_screen_perception_session",
    );
  }
}

export const screenPerceptionSettingsService =
  new ScreenPerceptionSettingsService();
