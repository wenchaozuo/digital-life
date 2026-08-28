import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { BodyRendererError, BodyRendererHost } from "../src/body/bodyRenderer";
import { PngBodyRenderer } from "../src/body/pngBodyRenderer";
import type { BodyRenderer } from "../src/body/bodyRenderer";
import type { BodySnapshot } from "../src/body/types";

const thinkingSnapshot: BodySnapshot = {
  resourcePath: "/body/thinking.png",
  state: "thinking",
};
const idleSnapshot: BodySnapshot = {
  resourcePath: "/body/idle.png",
  state: "idle",
};

describe("PngBodyRenderer", () => {
  it("mounts exactly one renderer-owned image inside the supplied host", () => {
    const host = document.createElement("div");
    const renderer = new PngBodyRenderer();
    renderer.mount(host);
    renderer.render(thinkingSnapshot);

    const images = host.querySelectorAll("img");
    expect(images.length).toBe(1);
    const image = images[0];
    expect(image.getAttribute("src")).toBe("/body/thinking.png");
    expect(image.getAttribute("alt")).toBe("Digital Life thinking body");
  });

  it("updates the same renderer-owned image without duplicating the tree", () => {
    const host = document.createElement("div");
    const renderer = new PngBodyRenderer();
    renderer.mount(host);
    renderer.render(thinkingSnapshot);
    const firstImage = host.querySelector("img");
    expect(firstImage).not.toBeNull();

    renderer.render(idleSnapshot);

    const images = host.querySelectorAll("img");
    expect(images.length).toBe(1);
    expect(images[0]).toBe(firstImage);
    expect(images[0].getAttribute("src")).toBe("/body/idle.png");
    expect(images[0].getAttribute("alt")).toBe("Digital Life idle body");
  });

  it("dispose removes the renderer-owned DOM and is safe to repeat", () => {
    const host = document.createElement("div");
    const renderer = new PngBodyRenderer();
    renderer.mount(host);
    renderer.render(thinkingSnapshot);
    expect(host.childElementCount).toBe(1);

    renderer.dispose();
    expect(host.childElementCount).toBe(0);

    expect(() => renderer.dispose()).not.toThrow();
  });

  it("renders no image before mount (deterministic renderer-level failure)", () => {
    const renderer = new PngBodyRenderer();
    expect(() => renderer.render(thinkingSnapshot)).toThrow(BodyRendererError);
  });

  it("production source uses only the supplied host, never global DOM queries", () => {
    const source = fs.readFileSync(
      path.join(process.cwd(), "src/body/pngBodyRenderer.ts"),
      "utf8",
    );
    expect(source).not.toMatch(/document\.querySelector/);
    expect(source).not.toMatch(/document\.getElementById/);
    expect(source).not.toMatch(/document\.body/);

    // Outside comments, the only document usage must be creating the one
    // renderer-owned image element; everything else operates on the host.
    const codeDocumentUses: string[] = [];
    for (const line of source.split("\n")) {
      const codeLine = line.replace(/\/\/.*/, "");
      const start = codeLine.indexOf("document.");
      if (start >= 0) {
        codeDocumentUses.push(codeLine.slice(start, start + "document.createElement(".length));
      }
    }
    expect(codeDocumentUses).toEqual(["document.createElement("]);
  });
});

class CountingRenderer implements BodyRenderer {
  readonly mountedHosts: HTMLElement[] = [];
  readonly renderCalls: BodySnapshot[] = [];
  disposeCalls = 0;

  async mount(host: HTMLElement): Promise<void> {
    this.mountedHosts.push(host);
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    this.renderCalls.push(snapshot);
  }

  dispose(): void {
    this.disposeCalls += 1;
  }
}

describe("BodyRendererHost", () => {
  it("rejects a render before mount with a bounded presentation error", async () => {
    const renderer = new CountingRenderer();
    const host = new BodyRendererHost(renderer);

    await expect(host.render(idleSnapshot)).rejects.toBeInstanceOf(BodyRendererError);
    expect(renderer.renderCalls.length).toBe(0);
  });

  it("mounts, forwards renders, and disposes the renderer exactly once", async () => {
    const renderer = new CountingRenderer();
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    await host.mount(element);
    await host.render(thinkingSnapshot);
    await host.render(idleSnapshot);
    expect(renderer.mountedHosts).toEqual([element]);
    expect(renderer.renderCalls).toEqual([thinkingSnapshot, idleSnapshot]);

    host.dispose();
    host.dispose(); // repeated disposal must not double-cleanup
    expect(renderer.disposeCalls).toBe(1);
  });

  it("treats a repeated mount of the same host idempotently", async () => {
    const renderer = new CountingRenderer();
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    await host.mount(element);
    await host.mount(element);
    expect(renderer.mountedHosts.length).toBe(1);
    expect(host.mounted()).toBe(true);
  });

  it("rejects a second mount onto a different host without a silent duplicate tree", async () => {
    const renderer = new CountingRenderer();
    const host = new BodyRendererHost(renderer);
    const first = document.createElement("div");
    const second = document.createElement("div");

    await host.mount(first);
    await expect(host.mount(second)).rejects.toBeInstanceOf(BodyRendererError);
    expect(renderer.mountedHosts.length).toBe(1);
    expect(host.mounted()).toBe(true);
  });
});

class ControlledRenderer implements BodyRenderer {
  readonly mountedHosts: HTMLElement[] = [];
  readonly renderCalls: BodySnapshot[] = [];
  disposeCalls = 0;
  mountRejects = false;
  disposeRejects = false;
  resolveMount: (() => void) | undefined;
  rejectMount: ((error: Error) => void) | undefined;
  private mountResult: Promise<void> | undefined;

  mount(host: HTMLElement): Promise<void> {
    this.mountedHosts.push(host);
    if (this.mountRejects) {
      this.mountResult = Promise.reject(new Error("mount failed"));
    } else {
      this.mountResult = new Promise<void>((resolve, reject) => {
        this.resolveMount = resolve;
        this.rejectMount = reject;
      });
    }
    return this.mountResult;
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    this.renderCalls.push(snapshot);
  }

  dispose(): Promise<void> | void {
    this.disposeCalls += 1;
    if (this.disposeRejects) {
      return Promise.reject(new Error("dispose failed"));
    }
  }

  settleMount(): void {
    if (this.mountRejects) {
      this.rejectMount?.(new Error("mount failed"));
    } else {
      this.resolveMount?.();
    }
  }
}

async function flushMicrotasks(rounds = 16): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

class SyncFailureRenderer implements BodyRenderer {
  mountSyncThrows = false;
  mountHeld = false;
  disposeSyncThrows = false;
  mountCalls = 0;
  renderCalls = 0;
  disposeCalls = 0;
  private resolveMount: (() => void) | undefined;
  private mountPromise: Promise<void> | undefined;

  mount(host: HTMLElement): Promise<void> | void {
    this.mountCalls += 1;
    if (this.mountSyncThrows) {
      throw new Error("sync mount failed");
    }
    if (this.mountHeld) {
      this.mountPromise = new Promise<void>((resolve) => {
        this.resolveMount = resolve;
      });
      return this.mountPromise;
    }
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    this.renderCalls += 1;
  }

  dispose(): Promise<void> | void {
    this.disposeCalls += 1;
    if (this.disposeSyncThrows) {
      throw new Error("sync dispose failed");
    }
  }

  settleMount(): void {
    this.resolveMount?.();
  }
}

describe("BodyRendererHost synchronous failure containment", () => {
  it("a synchronous mount throw rolls back and allows a real retry", async () => {
    const renderer = new SyncFailureRenderer();
    renderer.mountSyncThrows = true;
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    await expect(host.mount(element)).rejects.toThrow("sync mount failed");
    expect(host.mounted()).toBe(false);
    await expect(host.render(thinkingSnapshot)).rejects.toBeInstanceOf(BodyRendererError);
    expect(renderer.renderCalls).toBe(0);

    // The rollback is real: a retry mounts successfully.
    renderer.mountSyncThrows = false;
    await host.mount(element);
    expect(host.mounted()).toBe(true);
    await host.render(idleSnapshot);
    expect(renderer.renderCalls).toBe(1);
  });

  it("a synchronous dispose throw is contained exactly once", async () => {
    const renderer = new SyncFailureRenderer();
    renderer.disposeSyncThrows = true;
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    await host.mount(element);
    expect(() => host.dispose()).not.toThrow();
    expect(host.mounted()).toBe(false);
    expect(renderer.disposeCalls).toBe(1);

    expect(() => host.dispose()).not.toThrow();
    expect(renderer.disposeCalls).toBe(1);

    await expect(host.render(idleSnapshot)).rejects.toBeInstanceOf(BodyRendererError);
    await expect(host.mount(element)).rejects.toBeInstanceOf(BodyRendererError);
  });

  it("a synchronous dispose throw after a pending mount settles is contained", async () => {
    const renderer = new SyncFailureRenderer();
    renderer.mountHeld = true;
    renderer.disposeSyncThrows = true;
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    const mountPromise = host.mount(element);
    host.dispose();

    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);
    try {
      renderer.settleMount();
      await mountPromise;
      await flushMicrotasks();
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }

    expect(unhandled).toEqual([]);
    expect(host.mounted()).toBe(false);
    expect(renderer.disposeCalls).toBe(1);
    await expect(host.render(idleSnapshot)).rejects.toBeInstanceOf(BodyRendererError);
    await expect(host.mount(element)).rejects.toBeInstanceOf(BodyRendererError);
  });
});

describe("BodyRendererHost async lifecycle", () => {
  it("never renders before an in-flight async mount completes", async () => {
    const renderer = new ControlledRenderer();
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    const mountPromise = host.mount(element);
    const renderPromise = host.render(thinkingSnapshot);
    await flushMicrotasks();
    expect(renderer.renderCalls.length).toBe(0);

    renderer.settleMount();
    await mountPromise;
    await renderPromise;
    expect(renderer.renderCalls).toEqual([thinkingSnapshot]);
    expect(host.mounted()).toBe(true);
  });

  it("mount failure rolls back to unmounted with bounded render errors and allows retry", async () => {
    const renderer = new ControlledRenderer();
    renderer.mountRejects = true;
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    await expect(host.mount(element)).rejects.toThrow("mount failed");
    expect(host.mounted()).toBe(false);
    await expect(host.render(thinkingSnapshot)).rejects.toBeInstanceOf(BodyRendererError);
    expect(renderer.renderCalls.length).toBe(0);

    // A later retry may mount successfully because the host is not disposed.
    renderer.mountRejects = false;
    const retry = host.mount(element);
    renderer.settleMount();
    await retry;
    expect(host.mounted()).toBe(true);
    await host.render(idleSnapshot);
    expect(renderer.renderCalls).toEqual([idleSnapshot]);
  });

  it("reuses the same in-flight mount for a concurrent same-host call", async () => {
    const renderer = new ControlledRenderer();
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    const first = host.mount(element);
    const second = host.mount(element);
    expect(renderer.mountedHosts.length).toBe(1);

    renderer.settleMount();
    await first;
    await second;
    expect(renderer.mountedHosts.length).toBe(1);
    expect(host.mounted()).toBe(true);
  });

  it("rejects a different host while a mount is pending without a second tree", async () => {
    const renderer = new ControlledRenderer();
    const host = new BodyRendererHost(renderer);
    const first = document.createElement("div");
    const second = document.createElement("div");

    const pending = host.mount(first);
    await expect(host.mount(second)).rejects.toBeInstanceOf(BodyRendererError);
    expect(renderer.mountedHosts.length).toBe(1);

    renderer.settleMount();
    await pending;
    expect(renderer.mountedHosts.length).toBe(1);
    expect(host.mounted()).toBe(true);
  });

  it("dispose during a pending mount never resurrects and disposes exactly once", async () => {
    const renderer = new ControlledRenderer();
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    const mountPromise = host.mount(element);
    host.dispose();
    expect(host.mounted()).toBe(false);

    renderer.settleMount();
    await mountPromise;
    await flushMicrotasks();

    expect(host.mounted()).toBe(false);
    expect(renderer.disposeCalls).toBe(1);
    await expect(host.render(idleSnapshot)).rejects.toBeInstanceOf(BodyRendererError);
    await expect(host.mount(element)).rejects.toBeInstanceOf(BodyRendererError);
  });

  it("contains an async dispose rejection without an unhandled rejection", async () => {
    const renderer = new ControlledRenderer();
    renderer.disposeRejects = true;
    const host = new BodyRendererHost(renderer);
    const element = document.createElement("div");

    const mountPromise = host.mount(element);
    renderer.settleMount();
    await mountPromise;
    await host.render(thinkingSnapshot);

    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };
    process.on("unhandledRejection", onUnhandled);
    try {
      host.dispose();
      await flushMicrotasks();
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }

    expect(unhandled).toEqual([]);
    expect(host.mounted()).toBe(false);
    host.dispose(); // repeated dispose: no second renderer.dispose
    expect(renderer.disposeCalls).toBe(1);
    await expect(host.render(idleSnapshot)).rejects.toBeInstanceOf(BodyRendererError);
  });
});

describe("main App renderer ownership shape", () => {
  it("App.vue owns the renderer host and no direct production body image", () => {
    const appSource = fs.readFileSync(path.join(process.cwd(), "src/App.vue"), "utf8");
    expect(appSource).toMatch(/bodyRendererHost/);
    expect(appSource).toMatch(/bodyRendererElement/);
    expect(appSource).toMatch(/class="body-renderer-host"/);
    expect(appSource).toMatch(/bodyStateMachine/);
    expect(appSource).toMatch(/bodyRenderCoordinator/);
    expect(appSource).not.toMatch(/<img/);
    expect(appSource).not.toMatch(/bodyResource/);
  });

  it("App.vue contains the renderer mount barrier and keeps long init independent", () => {
    const appSource = fs.readFileSync(path.join(process.cwd(), "src/App.vue"), "utf8");
    expect(appSource).toMatch(/bodyRendererHost\.mount\(/);
    expect(appSource).toMatch(/rendererMount\.catch\(/, "mount rejection must be contained");
    expect(appSource).not.toMatch(
      /^[ \t]*bodyRendererHost\.mount\(/m,
      "mount must not be a fire-and-forget statement",
    );

    const mountAt = appSource.indexOf("bodyRendererHost.mount(");
    const storageInitAt = appSource.indexOf("await storageService.initialize()");
    const lifeInitAt = appSource.indexOf("await initializeDefaultLife()");
    expect(mountAt).toBeGreaterThanOrEqual(0);
    expect(storageInitAt).toBeGreaterThan(mountAt);
    expect(lifeInitAt).toBeGreaterThan(mountAt);
  });

  it("ChatView never touches the renderer surface", () => {
    const chatSource = fs.readFileSync(
      path.join(process.cwd(), "src/chat/ChatView.vue"),
      "utf8",
    );
    expect(chatSource).not.toMatch(/BodyRenderer/);
    expect(chatSource).not.toMatch(/PngBodyRenderer/);
    expect(chatSource).not.toMatch(/body-renderer-host/);
  });
});