import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  BodyRendererError,
  FallbackBodyRenderer,
  PngBodyRenderer,
} from "../src/body/index";
import { BODY_STATES, type BodySnapshot, type BodyState } from "../src/body/types";
import {
  Live2DBrowserTestRenderer,
  type Live2DBrowserEngine,
  type Live2DBrowserRendererConfig,
} from "../src/body/live2dBrowserTestRenderer";

const MODEL_URL =
  "https://raw.githubusercontent.com/Live2D/CubismWebSamples/b1de66b0b1f1cb881d95fb6158622aeb6a2827bd/Samples/Resources/Haru/Haru.model3.json";

const snapshotFor = (state: BodyState): BodySnapshot => ({
  resourcePath: `/controlled/${state}.png`,
  state,
});

class Deferred {
  readonly promise: Promise<void>;
  private resolvePromise!: () => void;

  constructor() {
    this.promise = new Promise<void>((resolve) => {
      this.resolvePromise = resolve;
    });
  }

  resolve(): void {
    this.resolvePromise();
  }
}

interface FakeEngineOptions {
  readonly failMount?: boolean;
  readonly pendingMount?: Deferred;
}

class FakeLive2DEngine implements Live2DBrowserEngine {
  readonly mountModelUrls: string[] = [];
  readonly renderedSnapshots: BodySnapshot[] = [];
  mountCalls = 0;
  disposeCalls = 0;
  modelCreated = 0;
  modelDestroyed = 0;
  private readonly options: FakeEngineOptions;
  private canvas: HTMLCanvasElement | undefined;
  private model: HTMLElement | undefined;

  constructor(options: FakeEngineOptions = {}) {
    this.options = options;
  }

  async mount(host: HTMLElement, modelUrl: string): Promise<void> {
    this.mountCalls += 1;
    this.mountModelUrls.push(modelUrl);
    const canvas = document.createElement("canvas");
    this.canvas = canvas;
    host.replaceChildren(canvas);

    if (this.options.pendingMount !== undefined) {
      await this.options.pendingMount.promise;
    }
    if (this.options.failMount) {
      throw new Error("controlled mount failure");
    }

    const model = document.createElement("span");
    model.dataset.fakeLive2dModel = "true";
    this.model = model;
    this.modelCreated += 1;
    host.append(model);
  }

  render(snapshot: BodySnapshot): void {
    if (this.model === undefined) {
      throw new Error("controlled model is not ready");
    }
    this.renderedSnapshots.push(snapshot);
  }

  dispose(): void {
    this.disposeCalls += 1;
    if (this.model !== undefined) {
      this.model.remove();
      this.model = undefined;
      this.modelDestroyed += 1;
    }
    this.canvas?.remove();
    this.canvas = undefined;
  }
}

function createRenderer(
  engine: FakeLive2DEngine,
  config: Live2DBrowserRendererConfig = { modelUrl: MODEL_URL },
): Live2DBrowserTestRenderer {
  return new Live2DBrowserTestRenderer(config, () => engine);
}

function readWorkspaceFile(relativePath: string): string {
  return fs.readFileSync(path.resolve(process.cwd(), relativePath), "utf8");
}

function sourceFilesUnder(relativePath: string): string[] {
  const root = path.resolve(process.cwd(), relativePath);
  if (!fs.existsSync(root)) {
    return [];
  }

  const files: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const entryPath = path.join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(entryPath);
      } else if (/\.(ts|vue|rs|sql)$/.test(entry.name)) {
        files.push(fs.readFileSync(entryPath, "utf8"));
      }
    }
  };
  visit(root);
  return files;
}

describe("Live2DBrowserTestRenderer", () => {
  it("does not allocate before mount and uses constructor model configuration", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine();
    let receivedConfig: Live2DBrowserRendererConfig | undefined;
    const renderer = new Live2DBrowserTestRenderer(
      { modelUrl: MODEL_URL },
      (config) => {
        receivedConfig = config;
        return engine;
      },
    );

    expect(host.childElementCount).toBe(0);
    expect(engine.mountCalls).toBe(0);

    await renderer.mount(host);

    expect(receivedConfig?.modelUrl).toBe(MODEL_URL);
    expect(engine.mountModelUrls).toEqual([MODEL_URL]);
    expect(host.querySelectorAll("canvas")).toHaveLength(1);
    expect(renderer.isMounted()).toBe(true);
    await renderer.dispose();
  });

  it("accepts every frozen body state without using resourcePath as model source", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine();
    const renderer = createRenderer(engine);

    await renderer.mount(host);
    for (const state of BODY_STATES) {
      await renderer.render(snapshotFor(state));
    }

    expect(engine.mountModelUrls).toEqual([MODEL_URL]);
    expect(engine.renderedSnapshots.map((snapshot) => snapshot.state)).toEqual([
      "idle",
      "thinking",
      "speaking",
      "waiting",
      "error",
    ]);
    expect(engine.mountModelUrls).not.toContain("/controlled/idle.png");
    await renderer.dispose();
  });

  it("rejects render before mount with a bounded error", async () => {
    const renderer = createRenderer(new FakeLive2DEngine());

    await expect(renderer.render(snapshotFor("idle"))).rejects.toBeInstanceOf(
      BodyRendererError,
    );
  });

  it("cleans a partial engine and host after mount failure", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine({ failMount: true });
    const renderer = createRenderer(engine);

    await expect(renderer.mount(host)).rejects.toBeInstanceOf(BodyRendererError);
    expect(host.childElementCount).toBe(0);
    expect(renderer.isMounted()).toBe(false);
    expect(engine.disposeCalls).toBe(1);

    await renderer.dispose();
    await renderer.dispose();
    expect(engine.disposeCalls).toBe(1);
  });

  it("disposes exactly once after a successful mount", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine();
    const renderer = createRenderer(engine);

    await renderer.mount(host);
    await renderer.dispose();
    await renderer.dispose();

    expect(host.childElementCount).toBe(0);
    expect(renderer.isMounted()).toBe(false);
    expect(engine.disposeCalls).toBe(1);
  });

  it("retires a late model after dispose during pending mount", async () => {
    const host = document.createElement("div");
    const pendingMount = new Deferred();
    const engine = new FakeLive2DEngine({ pendingMount });
    const renderer = createRenderer(engine);

    const mountPromise = renderer.mount(host);
    expect(host.querySelector("canvas")).not.toBeNull();
    const disposePromise = renderer.dispose();

    pendingMount.resolve();
    await expect(mountPromise).resolves.toBeUndefined();
    await disposePromise;

    expect(engine.modelCreated).toBe(1);
    expect(engine.modelDestroyed).toBe(1);
    expect(engine.disposeCalls).toBe(1);
    expect(host.childElementCount).toBe(0);
    expect(renderer.isMounted()).toBe(false);
  });
});

describe("Live2D PNG fallback compatibility", () => {
  it("passes the same snapshot to the real PNG fallback", async () => {
    const host = document.createElement("div");
    const primary = createRenderer(
      new FakeLive2DEngine({ failMount: true }),
      { modelUrl: MODEL_URL },
    );
    const fallback = new PngBodyRenderer();
    const renderer = new FallbackBodyRenderer(primary, fallback);
    const snapshot = snapshotFor("thinking");

    await renderer.mount(host);
    await renderer.render(snapshot);

    const image = host.querySelector("img");
    expect(image).not.toBeNull();
    expect(image?.getAttribute("src")).toBe(snapshot.resourcePath);
    expect(image?.getAttribute("alt")).toBe("Digital Life thinking body");

    await renderer.dispose();
  });
});

describe("D21 browser boundary", () => {
  it("keeps the experimental renderer out of frozen production composition", () => {
    const appSource = readWorkspaceFile("src/App.vue");
    const packageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    const bindingSource = readWorkspaceFile("src/body/bodyBinding.ts");
    const barrelSource = readWorkspaceFile("src/body/index.ts");
    const rendererSource = readWorkspaceFile(
      "src/body/live2dBrowserTestRenderer.ts",
    );
    const runtimeSource = readWorkspaceFile("src/body/live2dBrowserRuntime.ts");

    expect(appSource).not.toMatch(/Live2D|live2d/i);
    expect(packageSource).not.toMatch(/Haru|Mark|Rice|@jannchie|live2dcubismcore/i);
    expect(bindingSource).not.toMatch(/Haru|Mark|Rice|@jannchie|live2dcubismcore/i);
    expect(barrelSource).not.toMatch(/Live2DBrowserTestRenderer|@jannchie|live2dcubismcore/i);
    expect(rendererSource).not.toMatch(/snapshot\.resourcePath/);
    expect(runtimeSource).not.toMatch(/snapshot\.resourcePath/);
    expect(runtimeSource).toContain("@jannchie/pixi-live2d-display/cubism4");
    expect(runtimeSource).not.toMatch(/node:path|node:fs|node:url|from ["']path["']/);

    for (const source of [...sourceFilesUnder("src/life"), ...sourceFilesUnder("src/storage")]) {
      expect(source).not.toMatch(/Haru|Mark|Rice|live2d/i);
    }
  });

  it("keeps the replacement dependency boundary exact and polyfill-free", () => {
    const packageSource = readWorkspaceFile("package.json");
    const lockSource = readWorkspaceFile("package-lock.json");

    expect(packageSource).toMatch(
      /"@jannchie\/pixi-live2d-display": "1\.4\.0"/,
    );
    expect(packageSource).toMatch(/"pixi\.js": "8\.20\.0"/);
    expect(packageSource).not.toMatch(/live2d-renderer|path-browserify|node-polyfill/i);
    expect(lockSource).not.toMatch(/live2d-renderer|node-polyfill/i);
    const jannchieRecord =
      lockSource.match(
        /"node_modules\/@jannchie\/pixi-live2d-display":[\s\S]*?(?=\n    "node_modules\/|$)/,
      )?.[0] ?? "";
    expect(jannchieRecord).not.toMatch(/path-browserify/i);
  });

  it("keeps the smoke harness on the pinned official model source", () => {
    const smokeSource = readWorkspaceFile("tests/live2d-smoke/main.ts");
    const notice = readWorkspaceFile("tests/live2d-smoke/THIRD_PARTY_NOTICES.md");

    expect(smokeSource).toContain("@jannchie/pixi-live2d-display/cubism4");
    expect(smokeSource).toContain("b1de66b0b1f1cb881d95fb6158622aeb6a2827bd");
    expect(smokeSource).toContain("Haru.model3.json");
    expect(smokeSource).toContain("Mark.model3.json");
    expect(smokeSource).toContain("Rice.model3.json");
    expect(smokeSource).not.toMatch(/node:path|node:fs|node:url/);
    expect(notice).toContain("Free Material License Agreement");
    expect(notice).toContain("not open-source");
    expect(notice).toContain("live2dcubismcore.min.js");
  });
});
