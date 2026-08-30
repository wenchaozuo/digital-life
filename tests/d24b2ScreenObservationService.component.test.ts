import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  MainScreenObservationService,
  screenObservationErrorFromUnknown,
} from "../src/perception/screenObservationService";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
});

describe("D24-B2 Main screen handoff service", () => {
  it("accepts candidateId in the bounded observation DTO", async () => {
    mockedInvoke.mockResolvedValue({
      capturedAt: "2026-08-30T00:00:00.000Z",
      status: "recognized",
      text: "screen text",
      truncated: false,
      candidateId: "candidate-a",
    });

    const service = new MainScreenObservationService();
    const observation = await service.observeNow("life-a");

    expect(observation.candidateId).toBe("candidate-a");
  });

  it("prepares with only lifeId and candidateId", async () => {
    mockedInvoke.mockResolvedValue({ grantId: "grant-opaque" });
    const service = new MainScreenObservationService();

    const grant = await service.prepareMainScreenContextForChat(
      "life-a",
      "candidate-a",
    );

    expect(mockedInvoke).toHaveBeenCalledTimes(1);
    expect(mockedInvoke).toHaveBeenCalledWith(
      "prepare_main_screen_context_for_chat",
      { lifeId: "life-a", candidateId: "candidate-a" },
    );
    expect(grant).toEqual({ grantId: "grant-opaque" });
  });

  it("converts unknown backend errors to bounded UI text", () => {
    const rawDetail = "C:/private/native-frame-and-grant";
    const error = screenObservationErrorFromUnknown({
      code: "UNKNOWN_NATIVE_ERROR",
      message: rawDetail,
      recoverable: false,
    });

    expect(error).toEqual({
      code: "SCREEN_OBSERVATION_UNAVAILABLE",
      message: "Screen observation is temporarily unavailable. Try again.",
      recoverable: true,
    });
    expect(error.message).not.toContain(rawDetail);
  });
});
