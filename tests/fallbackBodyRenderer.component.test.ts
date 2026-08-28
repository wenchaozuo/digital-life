import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  BodyRendererError,
  BodyRendererHost,
  FallbackBodyRenderer,
  createDefaultBodyRenderer,
  type BodyRenderer,
} from "../src/body/index";
import type { BodySnapshot } from "../src/body/types";

const thinkingSnapshot: BodySnapshot = {
  resourcePath: "/body/thinking.png",
  state: "thinking",
};
const speakingSnapshot: BodySnapshot = {
  resourcePath: "/body/speaking.png",
  state: "speaking",
};
const waitingSnapshot: BodySnapshot = {
  resourcePath: "/body/waiting.png",
  state: "waiting",
};

type FailureMode = "none" | "sync" | "async";

class FakeRenderer implements BodyRenderer {
  readonly mountedHosts: HTMLElement[] = [];
  readonly renderedSnapshots: BodySnapshot[] = [];
  readonly name: string;
  mountFailure: FailureMode = "none";
  renderFailures: FailureMode[] = [];
  disposeFailure: FailureMode = "none";
  disposeCalls = 0;
  private currentHost: HTMLElement | undefined;

  constructor(name: string) {
    this.name = name;
  }

  mount(host: HTMLElement): Promise<void> | void {
    this.mountedHosts.push(host);
    this.currentHost = host;
    const marker = document.createElement("span");
    marker.dataset.renderer = this.name;
    host.append(marker);

    if (this.mountFailure === "sync") {
      throw new Error(`${this.name} mount failed synchronously`);
    }
    if (this.mountFailure === "async") {
      return Promise.reject(new Error(`${this.name} mount failed asynchronously`));
    }
  }

  render(snapshot: BodySnapshot): Promise<void> | void {
    this.renderedSnapshots.push(snapshot);
    const failure = this.renderFailures.shift() ?? "none";
    if (failure === "sync") {
      throw new Error(`${this.name} render failed synchronously`);
    }
    if (failure === "async") {
      return Promise.reject(new Error(`${this.name} render failed asynchronously`));
    }
  }

  dispose(): Promise<void> | void {
    this.disposeCalls += 1;
    this.currentHost = undefined;
    if (this.disposeFailure === "sync") {
      throw new Error(`${this.name} dispose failed synchronously`);
    }
    if (this.disposeFailure === "async") {
      return Promise.reject(new Error(`${this.name} dispose failed asynchronously`));
    }
  }
}

async function flushMicrotasks(rounds = 8): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

describe("FallbackBodyRenderer", () => {
  it("keeps the fallback unmounted when primary mount succeeds", async () => {
    const primary = new FakeRenderer("primary");
    const fallback = new FakeRenderer("fallback");
    const renderer = new FallbackBodyRenderer(primary, fallback);
    const host = document.createElement("div");

    await renderer.mount(host);
    await renderer.render(thinkingSnapshot);

    expect(primary.mountedHosts).toEqual([host]);
    expect(primary.renderedSnapshots).toEqual([thinkingSnapshot]);
    expect(fallback.mountedHosts).toEqual([]);
    expect(fallback.renderedSnapshots).toEqual([]);
  });

  it.each(["sync", "async"] as const)(
    "activates fallback after a %s primary mount failure",
    async (failure) => {
      const primary = new FakeRenderer("primary");
      primary.mountFailure = failure;
      const fallback = new FakeRenderer("fallback");
      const renderer = new FallbackBodyRenderer(primary, fallback);
      const host = document.createElement("div");

      await renderer.mount(host);
      await renderer.render(thinkingSnapshot);

      expect(primary.mountedHosts).toEqual([host]);
      expect(primary.disposeCalls).toBe(1);
      expect(fallback.mountedHosts).toEqual([host]);
      expect(fallback.renderedSnapshots).toEqual([thinkingSnapshot]);
      expect(host.querySelector('[data-renderer="primary"]')).toBeNull();
      expect(host.querySelector('[data-renderer="fallback"]')).not.toBeNull();
    },
  );

  it.each(["sync", "async"] as const)(
    "fails over the same snapshot after a %s primary render failure",
    async (failure) => {
      const primary = new FakeRenderer("primary");
      primary.renderFailures = [failure];
      const fallback = new FakeRenderer("fallback");
      const renderer = new FallbackBodyRenderer(primary, fallback);
      const host = document.createElement("div");

      await renderer.mount(host);
      await renderer.render(speakingSnapshot);

      expect(primary.renderedSnapshots).toEqual([speakingSnapshot]);
      expect(primary.disposeCalls).toBe(1);
      expect(fallback.mountedHosts).toEqual([host]);
      expect(fallback.renderedSnapshots).toEqual([speakingSnapshot]);
      expect(host.querySelector('[data-renderer="primary"]')).toBeNull();

      await renderer.render(waitingSnapshot);

      expect(primary.renderedSnapshots).toEqual([speakingSnapshot]);
      expect(fallback.mountedHosts).toEqual([host]);
      expect(fallback.renderedSnapshots).toEqual([
        speakingSnapshot,
        waitingSnapshot,
      ]);
    },
  );

  it.each(["sync", "async"] as const)(
    "contains a %s primary cleanup failure while activating fallback",
    async (failure) => {
      const primary = new FakeRenderer("primary");
      primary.renderFailures = ["async"];
      primary.disposeFailure = failure;
      const fallback = new FakeRenderer("fallback");
      const renderer = new FallbackBodyRenderer(primary, fallback);
      const host = document.createElement("div");

      await renderer.mount(host);
      await expect(renderer.render(thinkingSnapshot)).resolves.toBeUndefined();

      expect(primary.disposeCalls).toBe(1);
      expect(fallback.mountedHosts).toEqual([host]);
      expect(fallback.renderedSnapshots).toEqual([thinkingSnapshot]);
    },
  );

  it("keeps fallback mode after activation failure and retries only fallback",
    async () => {
      const primary = new FakeRenderer("primary");
      primary.renderFailures = ["async"];
      const fallback = new FakeRenderer("fallback");
      fallback.mountFailure = "async";
      const renderer = new FallbackBodyRenderer(primary, fallback);
      const host = document.createElement("div");

      await renderer.mount(host);
      await expect(renderer.render(speakingSnapshot)).rejects.toBeInstanceOf(
        BodyRendererError,
      );

      fallback.mountFailure = "none";
      await renderer.render(waitingSnapshot);

      expect(primary.disposeCalls).toBe(1);
      expect(primary.renderedSnapshots).toEqual([speakingSnapshot]);
      expect(fallback.mountedHosts).toEqual([host, host]);
      expect(fallback.renderedSnapshots).toEqual([waitingSnapshot]);
      expect(host.querySelector('[data-renderer="primary"]')).toBeNull();
    },
  );

  it("does not re-enter primary after a fallback render failure", async () => {
    const primary = new FakeRenderer("primary");
    primary.renderFailures = ["async"];
    const fallback = new FakeRenderer("fallback");
    const renderer = new FallbackBodyRenderer(primary, fallback);
    const host = document.createElement("div");

    await renderer.mount(host);
    await renderer.render(thinkingSnapshot);
    fallback.renderFailures = ["async"];

    await expect(renderer.render(speakingSnapshot)).rejects.toBeInstanceOf(
      BodyRendererError,
    );
    await renderer.render(waitingSnapshot);

    expect(primary.renderedSnapshots).toEqual([thinkingSnapshot]);
    expect(fallback.renderedSnapshots).toEqual([
      thinkingSnapshot,
      speakingSnapshot,
      waitingSnapshot,
    ]);
  });

  it("surfaces both mount failures as a bounded host failure without ghost mounting", async () => {
    const primary = new FakeRenderer("primary");
    primary.mountFailure = "sync";
    const fallback = new FakeRenderer("fallback");
    fallback.mountFailure = "async";
    const renderer = new FallbackBodyRenderer(primary, fallback);
    const owner = new BodyRendererHost(renderer);
    const host = document.createElement("div");

    await expect(owner.mount(host)).rejects.toBeInstanceOf(BodyRendererError);
    expect(owner.mounted()).toBe(false);
    await expect(owner.render(thinkingSnapshot)).rejects.toBeInstanceOf(
      BodyRendererError,
    );
    owner.dispose();
    await renderer.dispose();

    expect(primary.disposeCalls).toBe(1);
    expect(fallback.disposeCalls).toBe(1);
    expect(host.childElementCount).toBe(0);
  });

  it("disposes each renderer once after failover, including repeated composite dispose",
    async () => {
      const primary = new FakeRenderer("primary");
      primary.renderFailures = ["async"];
      const fallback = new FakeRenderer("fallback");
      const renderer = new FallbackBodyRenderer(primary, fallback);
      const owner = new BodyRendererHost(renderer);
      const host = document.createElement("div");

      await owner.mount(host);
      await owner.render(thinkingSnapshot);
      owner.dispose();
      await renderer.dispose();
      await renderer.dispose();

      expect(primary.disposeCalls).toBe(1);
      expect(fallback.disposeCalls).toBe(1);
      expect(owner.mounted()).toBe(false);
    },
  );

  it("is safe to dispose before it is ever mounted", async () => {
    const primary = new FakeRenderer("primary");
    const fallback = new FakeRenderer("fallback");
    const renderer = new FallbackBodyRenderer(primary, fallback);

    await renderer.dispose();
    await renderer.dispose();

    expect(primary.disposeCalls).toBe(0);
    expect(fallback.disposeCalls).toBe(0);
  });
});

describe("default body renderer composition", () => {
  it("creates fresh production compositions with a real PNG fallback", async () => {
    const first = createDefaultBodyRenderer();
    const second = createDefaultBodyRenderer();
    const host = document.createElement("div");

    expect(first).not.toBe(second);
    await first.mount(host);
    await first.render(thinkingSnapshot);

    const image = host.querySelector("img");
    expect(image).not.toBeNull();
    expect(image?.getAttribute("src")).toBe(thinkingSnapshot.resourcePath);
    await first.dispose();
    await second.dispose();

    const indexSource = fs.readFileSync(
      path.join(process.cwd(), "src/body/index.ts"),
      "utf8",
    );
    expect(indexSource).toMatch(
      /new FallbackBodyRenderer\(\s*new PngBodyRenderer\(\),\s*new PngBodyRenderer\(\),/s,
    );

    const appSource = fs.readFileSync(
      path.join(process.cwd(), "src/App.vue"),
      "utf8",
    );
    expect(appSource).toContain("createBodyPresentationForBodyId(life.bodyId)");
    expect(appSource).not.toContain("createDefaultBodyRenderer()");
    expect(appSource).not.toMatch(/new PngBodyRenderer/);
  });
});
