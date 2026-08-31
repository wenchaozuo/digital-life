import { invoke } from "@tauri-apps/api/core";

export interface ChatScreenContextAttachmentStatus {
  readonly available: boolean;
  readonly attachmentId?: string;
}

export interface ChatScreenContextAttachmentError {
  readonly code: string;
  readonly message: string;
  readonly recoverable: boolean;
}

const CHAT_ATTACHMENT_ERROR_MESSAGES: Record<string, string> = {
  SCREEN_CONTEXT_ATTACHMENT_INVALID_ARGUMENT:
    "The screen context attachment request is invalid.",
  SCREEN_CONTEXT_ATTACHMENT_NOT_FOUND:
    "The screen context attachment is no longer available.",
  SCREEN_CONTEXT_ATTACHMENT_BROKER_UNAVAILABLE:
    "The screen context attachment is temporarily unavailable. Try again.",
  SCREEN_CONTEXT_LIFE_UNAVAILABLE:
    "The current Life could not be verified. Try again.",
  SCREEN_CONTEXT_CONSENT_UNAVAILABLE:
    "Screen-perception consent could not be verified. Try again.",
};

/**
 * Keeps Chat attachment failures bounded.  Unknown Tauri/native payloads are
 * intentionally reduced to one generic recoverable presentation message.
 */
export function screenContextAttachmentErrorFromUnknown(
  caught: unknown,
): ChatScreenContextAttachmentError {
  if (typeof caught === "object" && caught !== null) {
    const candidate = caught as { code?: unknown; recoverable?: unknown };
    if (
      typeof candidate.code === "string" &&
      CHAT_ATTACHMENT_ERROR_MESSAGES[candidate.code] !== undefined
    ) {
      return {
        code: candidate.code,
        message: CHAT_ATTACHMENT_ERROR_MESSAGES[candidate.code],
        recoverable:
          typeof candidate.recoverable === "boolean"
            ? candidate.recoverable
            : candidate.code !== "SCREEN_CONTEXT_ATTACHMENT_INVALID_ARGUMENT",
      };
    }
  }

  return {
    code: "SCREEN_CONTEXT_ATTACHMENT_UNAVAILABLE",
    message: "The screen context attachment is temporarily unavailable. Try again.",
    recoverable: true,
  };
}

export class ScreenContextAttachmentService {
  async getPendingAttachment(): Promise<ChatScreenContextAttachmentStatus> {
    return invoke<ChatScreenContextAttachmentStatus>(
      "get_pending_screen_context_attachment",
    );
  }

  async dismissPendingAttachment(attachmentId: string): Promise<void> {
    return invoke<void>("dismiss_pending_screen_context_attachment", {
      attachmentId,
    });
  }
}

export const screenContextAttachmentService = new ScreenContextAttachmentService();
