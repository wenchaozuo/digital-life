import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  BodyRendererError,
  BodyRendererHost,
  FallbackBodyRenderer,
  PngBodyRenderer,
  createDefaultBodyRenderer,
} from "../src/body/index";
import type { BodyRenderer } from "../src/body/bodyRenderer";
import {
  BODY_STATES,
  type BodySnapshot,
  type BodyState,
} from "../src/body/types";
import {
  Live2DCoreUnavailableError,
  Live2DRenderer,
  calculateLive2DModelLayout,
  createLive2DCoreReadyBoundary,
  createPixiCubism4Live2DEngine,
  measureLive2DHost,
  normalizeLive2DHostSize,
  type Live2DCoreReadyBoundary,
  type Live2DEngine,
  type Live2DRendererConfig,
} from "../src/body/live2dRenderer";

const MODEL_URL =
  "https://raw.githubusercontent.com/Live2D/CubismWebSamples/b1de66b0b1f1cb881d95fb6158622aeb6a2827bd/Samples/Resources/Haru/Haru.model3.json";

const READY: Live2DCoreReadyBoundary = {
  ensureReady(): void {},
};

const snapshotFor = (state: BodyState, resourcePath = `/controlled/${state}.png`): BodySnapshot => ({
  resourcePath,
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
  readonly renderGates?: Deferred[];
  readonly rejectDispose?: boolean;
}

class FakeLive2DEngine implements Live2DEngine {
  readonly mountModelUrls: string[] = [];
  readonly renderedSnapshots: BodySnapshot[] = [];
  mountCalls = 0;
  resizeCalls = 0;
  disposeCalls = 0;
  modelCreated = 0;
  modelDestroyed = 0;
  private readonly options: FakeEngineOptions;
  private readonly configuredModelUrl: string;
  private canvas: HTMLCanvasElement | undefined;
  private model: HTMLElement | undefined;

  constructor(
    options: FakeEngineOptions = {},
    configuredModelUrl = MODEL_URL,
  ) {
    this.options = options;
    this.configuredModelUrl = configuredModelUrl;
  }

  async mount(host: HTMLElement): Promise<void> {
    this.mountCalls += 1;
    this.mountModelUrls.push(this.configuredModelUrl);
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

  resize(): void {
    if (this.model === undefined) {
      throw new Error("controlled model is not ready");
    }
    this.resizeCalls += 1;
    this.canvas?.setAttribute("data-fake-resized", String(this.resizeCalls));
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    if (this.model === undefined) {
      throw new Error("controlled model is not ready");
    }
    this.renderedSnapshots.push(snapshot);
    const gate = this.options.renderGates?.shift();
    if (gate !== undefined) {
      await gate.promise;
    }
  }

  dispose(): Promise<void> | void {
    this.disposeCalls += 1;
    if (this.model !== undefined) {
      this.model.remove();
      this.model = undefined;
      this.modelDestroyed += 1;
    }
    this.canvas?.remove();
    this.canvas = undefined;
    if (this.options.rejectDispose) {
      return Promise.reject(new Error("controlled dispose failure"));
    }
  }
}

function createRenderer(
  engine: FakeLive2DEngine,
  config: Live2DRendererConfig = { modelUrl: MODEL_URL, coreReady: READY },
): Live2DRenderer {
  return new Live2DRenderer(config, () => engine);
}

function readWorkspaceFile(relativePath: string): string {
  return fs.readFileSync(path.resolve(process.cwd(), relativePath), "utf8");
}

function sourceFilesUnder(
  relativePath: string,
  exclude?: (name: string) => boolean,
): string[] {
  const root = path.resolve(process.cwd(), relativePath);
  const files: string[] = [];
  const visit = (directory: string): void => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (exclude?.(entry.name) === true) {
        continue;
      }
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

async function flushMicrotasks(rounds = 12): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

describe("Live2DRenderer Core and source boundary", () => {
  it("fails boundedly before allocating when Cubism Core is absent", async () => {
    const host = document.createElement("div");
    const engine = createPixiCubism4Live2DEngine({
      modelUrl: MODEL_URL,
      coreReady: createLive2DCoreReadyBoundary(),
    });

    await expect(engine.mount(host)).rejects.toBeInstanceOf(
      Live2DCoreUnavailableError,
    );
    expect(host.childElementCount).toBe(0);
    await engine.dispose();
  });

  it("contains no remote Core fetch or script injection in production source", () => {
    // D22-D2: managedCubismCore.ts is the one sanctioned script-injection
    // seam. The Settings service is also excluded because it owns only the
    // fixed filename used by its exact picker check; it has no script or
    // renderer authority.
    for (const source of sourceFilesUnder(
      "src",
      (name) =>
        name === "managedCubismCore.ts" ||
        name === "live2dCoreSettingsService.ts",
    )) {
      expect(source).not.toMatch(
        /https:\/\/cubism\.live2d\.com|live2dcubismcore\.min\.js/i,
      );
      expect(source).not.toMatch(/script\.src\s*=|append\(\s*script\s*\)/i);
    }

    const runtimeSource = readWorkspaceFile("src/body/live2dRuntime.ts");
    expect(runtimeSource).toContain("coreReady.ensureReady()");
    expect(runtimeSource).toContain(
      "@jannchie/pixi-live2d-display/cubism4",
    );
    expect(runtimeSource).not.toMatch(/snapshot\.resourcePath/);
  });

  it("uses immutable renderer configuration as the model source", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine();
    const renderer = createRenderer(engine, {
      modelUrl: MODEL_URL,
      coreReady: READY,
    });

    await renderer.mount(host);
    await renderer.render(
      snapshotFor("idle", "/untrusted/snapshot-resource.png"),
    );

    expect(engine.mountModelUrls).toEqual([MODEL_URL]);
    expect(engine.renderedSnapshots[0]?.resourcePath).toBe(
      "/untrusted/snapshot-resource.png",
    );
    await renderer.dispose();
  });
});

describe("Live2DRenderer lifecycle", () => {
  it("does not allocate before mount and supports same-host idempotency", async () => {
    const host = document.createElement("div");
    const otherHost = document.createElement("div");
    const engine = new FakeLive2DEngine();
    const renderer = createRenderer(engine);

    expect(engine.mountCalls).toBe(0);
    await renderer.mount(host);
    await renderer.mount(host);

    expect(engine.mountCalls).toBe(1);
    await expect(renderer.mount(otherHost)).rejects.toBeInstanceOf(
      BodyRendererError,
    );
    await renderer.dispose();
  });

  it("rejects a different concurrent host without creating a second tree", async () => {
    const firstHost = document.createElement("div");
    const secondHost = document.createElement("div");
    const pendingMount = new Deferred();
    const engine = new FakeLive2DEngine({ pendingMount });
    const renderer = createRenderer(engine);

    const pending = renderer.mount(firstHost);
    await expect(renderer.mount(secondHost)).rejects.toBeInstanceOf(
      BodyRendererError,
    );
    expect(engine.mountCalls).toBe(1);
    expect(secondHost.childElementCount).toBe(0);

    pendingMount.resolve();
    await pending;
    await renderer.dispose();
  });

  it("rejects render before mount with a bounded error", async () => {
    const renderer = createRenderer(new FakeLive2DEngine());

    await expect(renderer.render(snapshotFor("idle"))).rejects.toBeInstanceOf(
      BodyRendererError,
    );
  });

  it("accepts every frozen BodyState without changing the model source", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine();
    const renderer = createRenderer(engine);

    await renderer.mount(host);
    for (const state of BODY_STATES) {
      await renderer.render(snapshotFor(state));
    }

    expect(engine.renderedSnapshots.map((snapshot) => snapshot.state)).toEqual([
      "idle",
      "thinking",
      "speaking",
      "waiting",
      "error",
    ]);
    expect(engine.mountModelUrls).toEqual([MODEL_URL]);
    await renderer.dispose();
  });

  it("waits for a pending mount before delivering a render", async () => {
    const host = document.createElement("div");
    const pendingMount = new Deferred();
    const engine = new FakeLive2DEngine({ pendingMount });
    const renderer = createRenderer(engine);

    const mountPromise = renderer.mount(host);
    const renderPromise = renderer.render(snapshotFor("thinking"));
    await flushMicrotasks();
    expect(engine.renderedSnapshots).toEqual([]);

    pendingMount.resolve();
    await mountPromise;
    await renderPromise;
    expect(engine.renderedSnapshots.map((snapshot) => snapshot.state)).toEqual([
      "thinking",
    ]);
    await renderer.dispose();
  });

  it("uses BodyRendererHost for serialized render delivery", async () => {
    const hostElement = document.createElement("div");
    const firstRender = new Deferred();
    const engine = new FakeLive2DEngine({ renderGates: [firstRender] });
    const renderer = createRenderer(engine);
    const host = new BodyRendererHost(renderer);

    await host.mount(hostElement);
    const first = host.render(snapshotFor("idle"));
    await flushMicrotasks();
    const second = host.render(snapshotFor("waiting"));
    await flushMicrotasks();

    expect(engine.renderedSnapshots.map((snapshot) => snapshot.state)).toEqual([
      "idle",
    ]);
    firstRender.resolve();
    await first;
    await second;
    expect(engine.renderedSnapshots.map((snapshot) => snapshot.state)).toEqual([
      "idle",
      "waiting",
    ]);
    host.dispose();
    await renderer.dispose();
  });

  it("retires late resources when disposed during pending mount", async () => {
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

  it("cleans partial mount failure and contains repeated disposal", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine({ failMount: true });
    const renderer = createRenderer(engine);

    await expect(renderer.mount(host)).rejects.toBeInstanceOf(BodyRendererError);
    expect(host.childElementCount).toBe(0);
    expect(engine.disposeCalls).toBe(1);
    await renderer.dispose();
    await renderer.dispose();
    expect(engine.disposeCalls).toBe(1);
  });

  it("contains renderer cleanup failure without an unhandled rejection", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine({ rejectDispose: true });
    const renderer = createRenderer(engine);
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown): void => {
      unhandled.push(reason);
    };

    await renderer.mount(host);
    process.on("unhandledRejection", onUnhandled);
    try {
      await renderer.dispose();
      await renderer.dispose();
      await flushMicrotasks();
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }

    expect(unhandled).toEqual([]);
    expect(engine.disposeCalls).toBe(1);
    expect(host.childElementCount).toBe(0);
  });
});

describe("Live2D sizing and PNG fallback", () => {
  it("normalizes zero-sized hosts and calculates deterministic fit geometry", () => {
    expect(normalizeLive2DHostSize(0, Number.NaN)).toEqual({
      width: 1,
      height: 1,
    });

    const layout = calculateLive2DModelLayout(
      { width: 480, height: 640 },
      { width: 240, height: 400 },
    );
    expect(layout.x).toBe(240);
    expect(layout.y).toBe(640);
    expect(layout.scale).toBeCloseTo(1.536, 6);
    expect(Number.isFinite(layout.scale)).toBe(true);
  });

  it("measures non-zero bounds and falls back safely when layout is zero", () => {
    const host = document.createElement("div");
    host.getBoundingClientRect = () =>
      ({ width: 320, height: 480 }) as DOMRect;
    expect(measureLive2DHost(host)).toEqual({ width: 320, height: 480 });

    host.getBoundingClientRect = () =>
      ({ width: 0, height: 0 }) as DOMRect;
    expect(measureLive2DHost(host)).toEqual({ width: 1, height: 1 });
  });

  it("forwards resize after mount without changing BodyRenderer contract", async () => {
    const host = document.createElement("div");
    const engine = new FakeLive2DEngine();
    const renderer = createRenderer(engine);

    await renderer.mount(host);
    await renderer.resize();

    expect(engine.resizeCalls).toBe(1);
    expect(host.querySelector("canvas")?.dataset.fakeResized).toBe("1");
    await renderer.dispose();
  });

  it("passes the same snapshot with intact state to PNG fallback", async () => {
    const host = document.createElement("div");
    const primary = createRenderer(new FakeLive2DEngine({ failMount: true }));
    const fallback = new PngBodyRenderer();
    const renderer = new FallbackBodyRenderer(primary, fallback);
    const snapshot = snapshotFor("thinking");

    await renderer.mount(host);
    await renderer.render(snapshot);

    const image = host.querySelector("img");
    expect(image?.getAttribute("src")).toBe(snapshot.resourcePath);
    expect(image?.getAttribute("alt")).toBe("Digital Life thinking body");
    await renderer.dispose();
  });
});

describe("D21 production composition and dependency boundaries", () => {
  it("keeps default-png production composition and App ownership unchanged", async () => {
    const renderer = createDefaultBodyRenderer();
    const host = document.createElement("div");
    const snapshot = snapshotFor("idle");

    await renderer.mount(host);
    await renderer.render(snapshot);
    expect(host.querySelector("img")?.getAttribute("src")).toBe(
      snapshot.resourcePath,
    );
    await renderer.dispose();

    const indexSource = readWorkspaceFile("src/body/index.ts");
    const packageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    const bindingSource = readWorkspaceFile("src/body/bodyBinding.ts");
    const appSource = readWorkspaceFile("src/App.vue");

    expect(indexSource).toMatch(
      /new FallbackBodyRenderer\(\s*new PngBodyRenderer\(\),\s*new PngBodyRenderer\(\),/s,
    );
    expect(packageSource).toContain('bodyId: DEFAULT_BODY_ID');
    expect(bindingSource).toContain('"live2d"');
    expect(bindingSource).not.toMatch(/Haru|Mark|Rice/i);
    expect(appSource).toMatch(/BodyRuntimeBindingController/);
    expect(appSource).toContain("createBodyPresentationForBodyId(bodyId)");
  });

  it("keeps the exact B1 dependency choice without application polyfills", () => {
    const packageSource = readWorkspaceFile("package.json");
    const lockSource = readWorkspaceFile("package-lock.json");
    const jannchieRecord =
      lockSource.match(
        /"node_modules\/@jannchie\/pixi-live2d-display":[\s\S]*?(?=\n    "node_modules\/|$)/,
      )?.[0] ?? "";

    expect(packageSource).toContain(
      '"@jannchie/pixi-live2d-display": "1.4.0"',
    );
    expect(packageSource).toContain('"pixi.js": "8.20.0"');
    expect(packageSource).not.toMatch(/live2d-renderer|path-browserify|node-polyfill/i);
    expect(lockSource).not.toMatch(/live2d-renderer|node-polyfill/i);
    expect(jannchieRecord).not.toMatch(/path-browserify/i);
  });

  it("preserves BodyRenderer, BodySnapshot, Coordinator, and bodyId contracts", () => {
    const rendererSource = readWorkspaceFile("src/body/bodyRenderer.ts");
    const snapshotSource = readWorkspaceFile("src/body/types.ts");
    const coordinatorSource = readWorkspaceFile(
      "src/body/bodyRenderCoordinator.ts",
    );
    const bodyPackageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    const newRendererSource = readWorkspaceFile("src/body/live2dRenderer.ts");

    expect(rendererSource).toMatch(/mount\(host: HTMLElement\)/);
    expect(rendererSource).toMatch(/render\(snapshot: BodySnapshot\)/);
    expect(rendererSource).toMatch(/dispose\(\)/);
    expect(snapshotSource).toContain("resourcePath: string;");
    expect(snapshotSource).toContain("state: BodyState;");
    expect(coordinatorSource).not.toMatch(/Live2D|live2d/i);
    expect(bodyPackageSource).not.toMatch(/Haru|Mark|Rice|@jannchie/i);
    expect(newRendererSource).not.toMatch(/snapshot\.resourcePath/);
    expect(newRendererSource).not.toMatch(/bodyId|model3|dynamic import key/i);
  });

  it("keeps the smoke-only remote Core/model boundary and notices", () => {
    const smokeSource = readWorkspaceFile("tests/live2d-smoke/main.ts");
    const noticeSource = readWorkspaceFile(
      "tests/live2d-smoke/THIRD_PARTY_NOTICES.md",
    );

    expect(smokeSource).toContain("live2dcubismcore.min.js");
    expect(smokeSource).toContain(
      "@jannchie/pixi-live2d-display/cubism4",
    );
    expect(smokeSource).toContain(
      "b1de66b0b1f1cb881d95fb6158622aeb6a2827bd",
    );
    expect(noticeSource).toContain("not open-source");
    expect(noticeSource).toContain("Free Material License Agreement");
    expect(noticeSource).toContain("proprietary Live2D software");
  });
});

describe("BodyRenderer type compatibility", () => {
  it("keeps Live2DRenderer assignable to the frozen renderer contract", () => {
    const renderer: BodyRenderer = new Live2DRenderer({
      modelUrl: MODEL_URL,
      coreReady: READY,
    });

    expect(renderer).toBeInstanceOf(Live2DRenderer);
  });
});
