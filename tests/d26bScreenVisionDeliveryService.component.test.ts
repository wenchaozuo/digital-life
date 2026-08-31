import { afterEach, describe, expect, it, vi } from "vitest";

import { invoke } from "@tauri-apps/api/core";

import {
  MainScreenVisionDeliveryService,
  createSecureVisionAttemptId,
  screenVisionDeliveryErrorFromUnknown,
} from "../src/perception/screenVisionDeliveryService";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("D26-B Main Vision delivery service boundary", () => {
  it("sends only backend-owned command shapes", async () => {
    const mockedInvoke = vi.mocked(invoke);
    mockedInvoke.mockResolvedValue(undefined);
    const service = new MainScreenVisionDeliveryService();

    await service.getStatus();
    expect(mockedInvoke).toHaveBeenLastCalledWith("get_main_screen_vision_status");

    await service.prepareReview();
    expect(mockedInvoke).toHaveBeenLastCalledWith("prepare_main_screen_vision_review");

    await service.executeReview("review-a", "confirmation-a", "delivery-a");
    expect(mockedInvoke).toHaveBeenLastCalledWith("execute_main_screen_vision_review", {
      request: {
        reviewId: "review-a",
        confirmationEventId: "confirmation-a",
        deliveryId: "delivery-a",
      },
    });

    await service.abandonDelivery("review-a");
    expect(mockedInvoke).toHaveBeenLastCalledWith("abandon_main_screen_vision_delivery", {
      request: { reviewId: "review-a" },
    });
  });

  it("uses a UUID-shaped secure fallback without timestamps or Math.random", () => {
    const values = new Uint8Array(16);
    values.fill(7);
    const fallbackCrypto = {
      getRandomValues<T extends ArrayBufferView>(array: T): T {
        const bytes = new Uint8Array(array.buffer, array.byteOffset, array.byteLength);
        bytes.set(values);
        return array;
      },
    } as Crypto;
    vi.stubGlobal("crypto", fallbackCrypto);

    const id = createSecureVisionAttemptId();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it("preserves the bounded definite-delivery terminal error", () => {
    expect(
      screenVisionDeliveryErrorFromUnknown({
        code: "VISION_TERMINAL_SETTLEMENT_UNAVAILABLE_AFTER_SEND",
        recoverable: false,
      }),
    ).toEqual({
      code: "VISION_TERMINAL_SETTLEMENT_UNAVAILABLE_AFTER_SEND",
      message:
        "The Vision provider received this image, but local one-shot finalization could not be completed. This attempt will not be resent automatically.",
      recoverable: false,
    });
  });
});
