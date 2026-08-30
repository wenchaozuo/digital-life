import { invoke } from "@tauri-apps/api/core";

export interface MainScreenPerceptionStatus {
  readonly consentEnabled: boolean;
  readonly sessionArmed: boolean;
  readonly targetSelected: boolean;
  readonly ready: boolean;
}

export type MainScreenObservationStatus = "recognized" | "noText";

export interface MainScreenObservation {
  readonly capturedAt: string;
  readonly status: MainScreenObservationStatus;
  readonly text: string;
  readonly truncated: boolean;
}

export interface MainScreenObservationError {
  readonly code: string;
  readonly message: string;
  readonly recoverable: boolean;
}

const SCREEN_OBSERVATION_ERROR_MESSAGES: Record<string, string> = {
  OBSERVATION_INVALID_ARGUMENT: "The screen observation request is invalid.",
  OBSERVATION_BUSY: "Another screen-perception operation is already in progress.",
  OBSERVATION_DISPATCH_FAILED: "The screen observation could not be dispatched.",
  OCR_UNAVAILABLE: "A usable local Windows OCR engine is unavailable.",
  OCR_FAILED: "Local screen OCR could not be completed.",
  OCR_TIMEOUT: "Local screen OCR exceeded its bounded time limit.",
  SESSION_DENIED: "Screen observation was not authorized for this session.",
  TARGET_REQUIRED: "No capture target is selected for this session.",
  TARGET_UNAVAILABLE: "The selected capture target is no longer available.",
  FRAME_INVALID: "The captured frame is invalid or out of bounds.",
  CAPTURE_FAILED: "The screen capture could not be completed.",
  SCREEN_PERCEPTION_STATUS_UNAVAILABLE:
    "Screen perception readiness is temporarily unavailable. Try again.",
};

/**
 * Keeps backend failures bounded before they reach the Main presentation.
 * Unknown Tauri errors never expose their raw payload or diagnostic text.
 */
export function screenObservationErrorFromUnknown(
  caught: unknown,
): MainScreenObservationError {
  if (typeof caught === "object" && caught !== null) {
    const candidate = caught as { code?: unknown; recoverable?: unknown };
    if (typeof candidate.code === "string") {
      const message = SCREEN_OBSERVATION_ERROR_MESSAGES[candidate.code];
      if (message !== undefined) {
        return {
          code: candidate.code,
          message,
          recoverable:
            typeof candidate.recoverable === "boolean"
              ? candidate.recoverable
              : true,
        };
      }
    }
  }

  return {
    code: "SCREEN_OBSERVATION_UNAVAILABLE",
    message: "Screen observation is temporarily unavailable. Try again.",
    recoverable: true,
  };
}

export class MainScreenObservationService {
  async getStatus(lifeId: string): Promise<MainScreenPerceptionStatus> {
    return invoke<MainScreenPerceptionStatus>(
      "get_main_screen_perception_status",
      { lifeId },
    );
  }

  async observeNow(lifeId: string): Promise<MainScreenObservation> {
    return invoke<MainScreenObservation>("observe_screen_now", { lifeId });
  }
}

export const mainScreenObservationService = new MainScreenObservationService();
