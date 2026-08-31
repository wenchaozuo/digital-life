import { invoke } from "@tauri-apps/api/core";

export interface ScreenVisionOutboundPolicy {
  lifeId: string;
  enabled: boolean;
  revision: number;
  createdAt: string;
  updatedAt: string;
}

export interface ScreenVisionOutboundSettingsError {
  readonly code: string;
  readonly message: string;
  readonly recoverable: boolean;
}

interface ScreenVisionOutboundPolicyLifeRequest {
  lifeId: string;
}

interface UpdateScreenVisionOutboundPolicyRequest
  extends ScreenVisionOutboundPolicyLifeRequest {
  enabled: boolean;
  expectedRevision: number;
  eventId: string;
}

const SCREEN_VISION_OUTBOUND_ERROR_MESSAGES: Readonly<Record<string, string>> = {
  SCREEN_VISION_OUTBOUND_INVALID_ARGUMENT:
    "The screen image sharing request is invalid.",
  SCREEN_VISION_OUTBOUND_LIFE_NOT_FOUND:
    "The selected Life could not be found.",
  SCREEN_VISION_OUTBOUND_POLICY_NOT_FOUND:
    "No screen-image sharing permission has been configured for this Life.",
  SCREEN_VISION_OUTBOUND_POLICY_DISABLED:
    "Screen image sharing permission is disabled for this Life.",
  SCREEN_VISION_OUTBOUND_POLICY_CONFLICT:
    "The screen image sharing permission changed before it was created.",
  SCREEN_VISION_OUTBOUND_POLICY_EVENT_CONFLICT:
    "This screen image sharing action conflicts with an existing action.",
  SCREEN_VISION_OUTBOUND_REVISION_CONFLICT:
    "This setting changed. Refresh the latest permission state before trying again.",
  SCREEN_VISION_OUTBOUND_INVALID_TRANSITION:
    "The screen image sharing permission is already in that state.",
  SCREEN_VISION_OUTBOUND_DATABASE_UNAVAILABLE:
    "Screen image sharing settings are temporarily unavailable. Try again.",
};

function createSecureEventId(): string {
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

export function screenVisionOutboundErrorFromUnknown(
  caught: unknown,
): ScreenVisionOutboundSettingsError {
  if (typeof caught === "object" && caught !== null) {
    const candidate = caught as { code?: unknown; recoverable?: unknown };
    if (typeof candidate.code === "string") {
      const safeMessage = SCREEN_VISION_OUTBOUND_ERROR_MESSAGES[candidate.code];
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
    code: "SCREEN_VISION_OUTBOUND_SETTINGS_UNAVAILABLE",
    message: "Screen image sharing settings could not be updated. Try again.",
    recoverable: true,
  };
}

export class ScreenVisionOutboundSettingsService {
  async getPolicy(lifeId: string): Promise<ScreenVisionOutboundPolicy | null> {
    return invoke<ScreenVisionOutboundPolicy | null>(
      "get_screen_vision_outbound_policy",
      {
        request: { lifeId } satisfies ScreenVisionOutboundPolicyLifeRequest,
      },
    );
  }

  async createPolicy(lifeId: string): Promise<ScreenVisionOutboundPolicy> {
    return invoke<ScreenVisionOutboundPolicy>(
      "create_screen_vision_outbound_policy",
      {
        request: { lifeId } satisfies ScreenVisionOutboundPolicyLifeRequest,
      },
    );
  }

  async updatePolicy(
    lifeId: string,
    enabled: boolean,
    expectedRevision: number,
  ): Promise<ScreenVisionOutboundPolicy> {
    return invoke<ScreenVisionOutboundPolicy>(
      "update_screen_vision_outbound_policy",
      {
        request: {
          eventId: createSecureEventId(),
          lifeId,
          enabled,
          expectedRevision,
        } satisfies UpdateScreenVisionOutboundPolicyRequest,
      },
    );
  }
}

export const screenVisionOutboundSettingsService =
  new ScreenVisionOutboundSettingsService();
