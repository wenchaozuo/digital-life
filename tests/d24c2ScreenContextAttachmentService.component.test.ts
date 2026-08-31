import { invoke } from "@tauri-apps/api/core";
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  ScreenContextAttachmentService,
  screenContextAttachmentErrorFromUnknown,
} from "../src/perception/screenContextAttachmentService";

vi.mock("@tauri-apps/api/core", () => ({ invoke: vi.fn() }));

const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
});

describe("D24-C2 Chat attachment service", () => {
  it("reads authoritative pending attachment status without Chat authority arguments", async () => {
    mockedInvoke.mockResolvedValue({ available: true, attachmentId: "opaque-attachment" });
    const service = new ScreenContextAttachmentService();

    const status = await service.getPendingAttachment();

    expect(mockedInvoke).toHaveBeenCalledWith("get_pending_screen_context_attachment");
    expect(status).toEqual({ available: true, attachmentId: "opaque-attachment" });
  });

  it("dismisses with only the exact opaque attachment ID", async () => {
    mockedInvoke.mockResolvedValue(undefined);
    const service = new ScreenContextAttachmentService();

    await service.dismissPendingAttachment("opaque-attachment");

    expect(mockedInvoke).toHaveBeenCalledWith(
      "dismiss_pending_screen_context_attachment",
      { attachmentId: "opaque-attachment" },
    );
  });

  it("maps known and unknown backend details to bounded recoverable text", () => {
    const rawDetail = "C:/private/native-attachment-state";
    expect(
      screenContextAttachmentErrorFromUnknown({
        code: "SCREEN_CONTEXT_ATTACHMENT_BROKER_UNAVAILABLE",
        message: rawDetail,
        recoverable: true,
      }),
    ).toEqual({
      code: "SCREEN_CONTEXT_ATTACHMENT_BROKER_UNAVAILABLE",
      message: "The screen context attachment is temporarily unavailable. Try again.",
      recoverable: true,
    });

    const unknown = screenContextAttachmentErrorFromUnknown({
      code: "UNKNOWN_NATIVE_ATTACHMENT_ERROR",
      message: rawDetail,
      recoverable: false,
    });
    expect(unknown.message).toContain("temporarily unavailable");
    expect(unknown.message).not.toContain(rawDetail);
  });
});
