import { invoke } from "@tauri-apps/api/core";

export type MainScreenVisionStatusKind =
  | "idle"
  | "reviewReady"
  | "deliveryInProgress"
  | "awaitingRetryDecision"
  | "definiteDeliveryObserved";

export interface MainScreenVisionReview {
  readonly reviewId: string;
  readonly scope: string;
  readonly width: number;
  readonly height: number;
  readonly providerKind: string;
  readonly providerHost: string;
  readonly profileDisplayName: string;
  readonly modelName: string;
}

export interface MainScreenVisionAttempt {
  readonly reviewId: string;
  readonly confirmationEventId: string;
  readonly deliveryId: string;
}

export interface MainScreenVisionStatus {
  readonly status: MainScreenVisionStatusKind;
  readonly review: MainScreenVisionReview | null;
}

export interface MainScreenVisionAnalysis {
  readonly summary: string;
  readonly observations: readonly string[];
  readonly providerDisplayName: string;
  readonly modelName: string;
  readonly visionResultId: string | null;
}

export interface MainScreenVisionContextHandoffOffer {
  readonly attachmentId: string;
}

export interface MainScreenVisionDeliveryError {
  readonly code: string;
  readonly message: string;
  readonly recoverable: boolean;
}

interface ExecuteMainScreenVisionReviewRequest {
  readonly reviewId: string;
  readonly confirmationEventId: string;
  readonly deliveryId: string;
}

interface AbandonMainScreenVisionDeliveryRequest {
  readonly reviewId: string;
}

interface OfferScreenVisionResultToChatRequest {
  readonly visionResultId: string;
}

const SCREEN_VISION_DELIVERY_ERROR_MESSAGES: Readonly<Record<string, string>> = {
  VISION_INVALID_ARGUMENT: "The Vision request is invalid.",
  VISION_LIFE_UNAVAILABLE: "The current Life could not be verified. Try again.",
  VISION_LOCAL_SCREEN_UNAVAILABLE:
    "Screen perception is not authorized for this session.",
  VISION_OUTBOUND_POLICY_UNAVAILABLE:
    "Screen image sharing is not currently authorized for this Life.",
  VISION_PROVIDER_UNAVAILABLE:
    "A valid active Vision provider is not available. Check Settings.",
  VISION_CREDENTIAL_UNAVAILABLE:
    "A Vision credential is not configured for the active profile.",
  VISION_TARGET_UNAVAILABLE: "The selected screen target is unavailable.",
  VISION_CAPTURE_UNAVAILABLE:
    "The selected screen target could not be captured.",
  VISION_REVIEW_IN_USE:
    "Another Vision review or delivery is already using this target.",
  VISION_REVIEW_UNAVAILABLE:
    "The Vision review is no longer available. Prepare again.",
  VISION_REVIEW_EXPIRED:
    "The Vision review expired. Prepare the screen again.",
  VISION_REVIEW_STALE:
    "The Vision destination changed. Prepare and review the screen again.",
  VISION_REVIEW_CONFLICT:
    "This Vision review does not match the current attempt.",
  VISION_DELIVERY_IN_PROGRESS: "A Vision delivery is already in progress.",
  VISION_CANDIDATE_UNAVAILABLE:
    "The prepared screen candidate is no longer available.",
  VISION_DELIVERY_UNAVAILABLE:
    "The Vision delivery authorization is unavailable.",
  VISION_DELIVERY_LEASE_UNAVAILABLE:
    "The prepared screen could not be reserved for this delivery.",
  VISION_PNG_ENCODING_FAILED:
    "The screen image could not be encoded for Vision.",
  VISION_PNG_TOO_LARGE:
    "The encoded screen image exceeds the allowed size.",
  VISION_REQUEST_TOO_LARGE: "The Vision request exceeds the allowed size.",
  VISION_NOT_SENT: "The image was not sent. You may retry this same attempt.",
  VISION_SEND_OUTCOME_UNKNOWN:
    "The image may have been sent. Retry only if you accept that it may be sent again to the same Vision provider.",
  VISION_PROVIDER_RESPONDED:
    "The Vision provider responded. Prepare a new image before trying again.",
  VISION_RESPONSE_INVALID_AFTER_SEND:
    "The image was sent, but the Vision response was invalid. Prepare a new analysis.",
  VISION_TERMINAL_SETTLEMENT_UNAVAILABLE_AFTER_SEND:
    "The Vision provider received this image, but local one-shot finalization could not be completed. This attempt will not be resent automatically.",
  VISION_ABANDON_UNAVAILABLE: "This Vision attempt can no longer be abandoned.",
  PERCEPTION_ATTACHMENT_IN_USE:
    "Another screen perception attachment is already reserved for Chat.",
  VISION_RESULT_UNAVAILABLE:
    "This Vision analysis is no longer available for Chat. Prepare a new analysis.",
  VISION_SYNCHRONIZATION_UNAVAILABLE:
    "Vision delivery is temporarily unavailable.",
};

export function createSecureVisionAttemptId(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }

  if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
    throw new Error("Secure Vision attempt identity generation is unavailable.");
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

export function screenVisionDeliveryErrorFromUnknown(
  caught: unknown,
): MainScreenVisionDeliveryError {
  if (typeof caught === "object" && caught !== null) {
    const candidate = caught as { code?: unknown; recoverable?: unknown };
    if (typeof candidate.code === "string") {
      const message = SCREEN_VISION_DELIVERY_ERROR_MESSAGES[candidate.code];
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
    code: "VISION_DELIVERY_UNAVAILABLE",
    message: "Vision delivery is temporarily unavailable.",
    recoverable: true,
  };
}

export class MainScreenVisionDeliveryService {
  async getStatus(): Promise<MainScreenVisionStatus> {
    return invoke<MainScreenVisionStatus>("get_main_screen_vision_status");
  }

  async prepareReview(): Promise<MainScreenVisionReview> {
    return invoke<MainScreenVisionReview>("prepare_main_screen_vision_review");
  }

  async executeReview(
    reviewId: string,
    confirmationEventId: string,
    deliveryId: string,
  ): Promise<MainScreenVisionAnalysis> {
    const request: ExecuteMainScreenVisionReviewRequest = {
      reviewId,
      confirmationEventId,
      deliveryId,
    };
    return invoke<MainScreenVisionAnalysis>("execute_main_screen_vision_review", {
      request,
    });
  }

  async abandonDelivery(reviewId: string): Promise<void> {
    const request: AbandonMainScreenVisionDeliveryRequest = { reviewId };
    return invoke<void>("abandon_main_screen_vision_delivery", { request });
  }

  async offerVisionResultToChat(
    visionResultId: string,
  ): Promise<MainScreenVisionContextHandoffOffer> {
    const request: OfferScreenVisionResultToChatRequest = { visionResultId };
    return invoke<MainScreenVisionContextHandoffOffer>(
      "offer_screen_vision_result_to_chat",
      { request },
    );
  }
}

export const mainScreenVisionDeliveryService =
  new MainScreenVisionDeliveryService();
