import { invoke } from "@tauri-apps/api/core";

/**
 * De-identified capture-target descriptor.  The backend never exposes an
 * HWND, PID, window title (as authority), process path, or monitor device
 * path; only a stable per-process index and a bounded display label.
 */
export interface ScreenCaptureTargetDescriptor {
  index: number;
  kind: "monitor" | "window" | string;
  label: string;
}

export interface ScreenCaptureTargetStatus {
  selected: ScreenCaptureTargetDescriptor | null;
}

export interface ScreenCaptureSmoke {
  width: number;
  height: number;
  pixelFormat: string;
}

export interface ScreenCaptureSettingsError {
  readonly code: string;
  readonly message: string;
  readonly recoverable: boolean;
}

interface ScreenCaptureTargetSelectionRequest {
  lifeId: string;
  selectionIndex: number;
}

const SCREEN_CAPTURE_ERROR_MESSAGES: Record<string, string> = {
  SCREEN_CAPTURE_NOT_SUPPORTED:
    "Screen capture is not supported on this device.",
  SCREEN_CAPTURE_TARGET_REQUIRED:
    "Select a capture target before capturing.",
  SCREEN_CAPTURE_TARGET_UNAVAILABLE:
    "The selected capture target is no longer available.",
  SCREEN_CAPTURE_SESSION_DENIED:
    "Screen capture is not authorized for this session.",
  SCREEN_CAPTURE_FRAME_INVALID:
    "The captured frame was invalid or out of bounds.",
  SCREEN_CAPTURE_FAILED:
    "The screen capture could not be completed.",
  SCREEN_CAPTURE_INVALID_ARGUMENT:
    "The screen capture request is invalid.",
};

export function screenCaptureErrorFromUnknown(
  caught: unknown,
): ScreenCaptureSettingsError {
  if (typeof caught === "object" && caught !== null) {
    const candidate = caught as { code?: unknown; recoverable?: unknown };
    if (typeof candidate.code === "string") {
      const safeMessage = SCREEN_CAPTURE_ERROR_MESSAGES[candidate.code];
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
    code: "SCREEN_CAPTURE_SETTINGS_UNAVAILABLE",
    message: "Screen capture settings could not be updated. Try again.",
    recoverable: true,
  };
}

export class ScreenCaptureSettingsService {
  async listTargets(): Promise<ScreenCaptureTargetDescriptor[]> {
    return invoke<ScreenCaptureTargetDescriptor[]>(
      "list_screen_capture_targets",
    );
  }

  async selectTarget(
    lifeId: string,
    selectionIndex: number,
  ): Promise<ScreenCaptureTargetDescriptor> {
    return invoke<ScreenCaptureTargetDescriptor>(
      "select_screen_capture_target",
      {
        request: { lifeId, selectionIndex } satisfies ScreenCaptureTargetSelectionRequest,
      },
    );
  }

  async getTargetStatus(): Promise<ScreenCaptureTargetStatus> {
    return invoke<ScreenCaptureTargetStatus>(
      "get_screen_capture_target_status",
    );
  }

  async clearTarget(): Promise<ScreenCaptureTargetStatus> {
    return invoke<ScreenCaptureTargetStatus>("clear_screen_capture_target");
  }

  async captureSmoke(lifeId: string): Promise<ScreenCaptureSmoke> {
    return invoke<ScreenCaptureSmoke>("capture_screen_smoke", {
      lifeId,
    });
  }
}

export const screenCaptureSettingsService = new ScreenCaptureSettingsService();
