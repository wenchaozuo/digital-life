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