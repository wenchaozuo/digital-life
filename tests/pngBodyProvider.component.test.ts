import { describe, expect, it } from "vitest";

import { PngBodyProvider } from "../src/body/pngBodyProvider";
import { BODY_STATES, type BodyState } from "../src/body/types";

// D17-B1 PNG fallback regression: the idle PNG remains the stable resource
// for every frozen body state.  Distinct images are not required.
describe("PngBodyProvider fallback", () => {
  it("returns a valid resource for every BODY_STATES value", async () => {
    const resourcePaths = new Set<string>();
    for (const state of BODY_STATES) {
      const provider = new PngBodyProvider();
      const snapshot = await provider.load(state);
      expect(snapshot.state).toBe(state);
      expect(snapshot.resourcePath.length).toBeGreaterThan(0);
      expect(snapshot.resourcePath).toContain("digital-life-idle");
      resourcePaths.add(snapshot.resourcePath);
    }
    expect(resourcePaths.size).toBe(1);
  });

  it("keeps the loaded state on the current snapshot", async () => {
    const provider = new PngBodyProvider();
    const states: BodyState[] = ["idle", "thinking", "waiting", "speaking", "error"];
    for (const state of states) {
      await provider.load(state);
      expect(provider.getCurrent().state).toBe(state);
    }
  });
});