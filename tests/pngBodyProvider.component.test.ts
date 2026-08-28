import { describe, expect, it } from "vitest";

import { FallbackBodyProvider } from "../src/body/fallbackBodyProvider";
import { PngBodyProvider } from "../src/body/pngBodyProvider";
import type { PngBodyResources } from "../src/body/pngBodyResources";
import { BODY_STATES, type BodyProvider, type BodySnapshot, type BodyState } from "../src/body/types";

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

// D17-C: a failing primary must always fall back to the real PNG provider
// with the requested state preserved.
class FailingBodyProvider implements BodyProvider {
  async load(_state: BodyState): Promise<BodySnapshot> {
    throw new Error("primary unavailable");
  }

  async switchState(_state: BodyState): Promise<BodySnapshot> {
    throw new Error("primary unavailable");
  }

  getCurrent(): BodySnapshot {
    throw new Error("primary unavailable");
  }
}

describe("FallbackBodyProvider with real PNG fallback", () => {
  it("returns a valid PNG snapshot for every BODY_STATES value when the primary fails", async () => {
    for (const state of BODY_STATES) {
      const provider = new FallbackBodyProvider(new FailingBodyProvider(), new PngBodyProvider());
      const snapshot = await provider.switchState(state);
      expect(snapshot.state).toBe(state, `requested state ${state} must be preserved`);
      expect(snapshot.resourcePath.length).toBeGreaterThan(0);
      expect(snapshot.resourcePath).toContain("digital-life-idle");
      expect(provider.getCurrent().state).toBe(state);
    }
  });
});

function customResources(): Record<BodyState, string> {
  return {
    idle: "idle-test.png",
    thinking: "thinking-test.png",
    speaking: "speaking-test.png",
    waiting: "waiting-test.png",
    error: "error-test.png",
  };
}

describe("parameterized PngBodyProvider", () => {
  it("uses the supplied resource for every frozen body state", async () => {
    const resources = customResources();
    const provider = new PngBodyProvider(resources);

    for (const state of BODY_STATES) {
      const snapshot = await provider.switchState(state);
      expect(snapshot).toEqual({
        resourcePath: resources[state],
        state,
      });
    }
  });

  it("defensively copies the caller resource set at construction", async () => {
    const resources = customResources();
    const provider = new PngBodyProvider(resources);

    resources.thinking = "mutated-after-construction.png";

    const snapshot = await provider.switchState("thinking");
    expect(snapshot.resourcePath).toBe("thinking-test.png");
  });

  it.each([
    [
      "missing state",
      {
        idle: "idle-test.png",
        thinking: "thinking-test.png",
        speaking: "speaking-test.png",
        waiting: "waiting-test.png",
      } as unknown as PngBodyResources,
    ],
    [
      "empty state",
      {
        ...customResources(),
        error: "",
      } as PngBodyResources,
    ],
  ] as const)("rejects an invalid %s resource set with a bounded error", (_label, resources) => {
    expect(() => new PngBodyProvider(resources)).toThrowError(
      "invalid PNG body resources.",
    );
  });
});
