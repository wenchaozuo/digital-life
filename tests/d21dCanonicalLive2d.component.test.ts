import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  BODY_STATES,
  BodyRenderCoordinator,
  BodyRendererError,
  BodyRendererHost,
  DEFAULT_BODY_ID,
  PngBodyProvider,
  createBodyPresentationForBodyId,
  resolveBodyBinding,
} from "../src/body";
import {
  createPackagePresentationForDefinition,
  resolveBodyPackage,
  resolveBodyPackageForTestCatalog,
} from "../src/body/bodyPackage";
import {
  createBodyPresentationForTestCatalog,
  resolveBodyBindingForTestCatalog,
} from "../src/body/bodyBinding";
import {
  createTrustedLocalLive2DModelSource,
  isTrustedLocalLive2DModelSource,
} from "../src/body/live2dModelSource";
import { Live2DCoreUnavailableError } from "../src/body/live2dRenderer";
import type { BodyRenderer } from "../src/body/bodyRenderer";
import type {
  Live2DCoreReadyBoundary,
  Live2DEngine,
  Live2DEngineFactory,
} from "../src/body/live2dRuntime";
import type { BodySnapshot, BodyState } from "../src/body/types";

const CONTROLLED_BODY_ID = "controlled-local-live2d";
const LOCAL_MODEL_PATH = "/bundled-test/controlled/controlled.model3.json";
const FALLBACK_RESOURCES = Object.freeze({
  idle: "/controlled/idle.png",
  thinking: "/controlled/thinking.png",
  speaking: "/controlled/speaking.png",
  waiting: "/controlled/waiting.png",
  error: "/controlled/error.png",
});

function snapshotFor(state: BodyState): BodySnapshot {
  return {
    resourcePath: FALLBACK_RESOURCES[state],
    state,
  };
}

function readyCore(): Live2DCoreReadyBoundary {
  return {
    ensureReady(): void {},
  };
}

function unavailableCore(onEnsureReady?: () => void): Live2DCoreReadyBoundary {
  return {
    ensureReady(): never {
      onEnsureReady?.();
      throw new Live2DCoreUnavailableError();
    },
  };
}

function createLive2DPackage(
  coreReady: Live2DCoreReadyBoundary = readyCore(),
  bodyId = CONTROLLED_BODY_ID,
) {
  return Object.freeze({
    bodyId,
    presentation: Object.freeze({
      kind: "live2d" as const,
      modelSource: createTrustedLocalLive2DModelSource(LOCAL_MODEL_PATH),
      coreReady,
      fallbackResources: FALLBACK_RESOURCES,
    }),
  });
}

function createCatalog(bodyPackage = createLive2DPackage()) {
  return Object.freeze({
    [bodyPackage.bodyId]: bodyPackage,
  });
}

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

interface ControlledEngineOptions {
  readonly pendingMount?: Deferred;
  readonly failMount?: boolean;
  readonly failRender?: boolean;
  readonly renderGate?: Deferred;
}

class ControlledLive2DEngine implements Live2DEngine {
  readonly options: ControlledEngineOptions;
  readonly renderedSnapshots: BodySnapshot[] = [];
  mountCalls = 0;
  disposeCalls = 0;
  modelCreated = 0;
  modelDestroyed = 0;
  private model: HTMLElement | undefined;
  private canvas: HTMLCanvasElement | undefined;

  constructor(options: ControlledEngineOptions = {}) {
    this.options = options;
  }

  async mount(host: HTMLElement): Promise<void> {
    this.mountCalls += 1;
    const canvas = document.createElement("canvas");
    canvas.dataset.controlledLive2d = "canvas";
    this.canvas = canvas;
    host.replaceChildren(canvas);

    if (this.options.pendingMount !== undefined) {
      await this.options.pendingMount.promise;
    }
    if (this.options.failMount) {
      throw new Error("controlled Live2D mount failure");
    }

    const model = document.createElement("span");
    model.dataset.controlledLive2d = "model";
    this.model = model;
    this.modelCreated += 1;
    host.append(model);
  }

  resize(): void {
    if (this.model === undefined) {
      throw new Error("controlled Live2D model is not mounted");
    }
    this.canvas?.setAttribute("data-controlled-resized", "true");
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    if (this.model === undefined) {
      throw new Error("controlled Live2D model is not mounted");
    }
    this.renderedSnapshots.push(snapshot);
    if (this.options.failRender) {
      throw new Error("controlled Live2D render failure");
    }
    if (this.options.renderGate !== undefined) {
      await this.options.renderGate.promise;
    }
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

function createCanonicalComposition(
  engine: ControlledLive2DEngine | undefined,
  coreReady: Live2DCoreReadyBoundary = readyCore(),
) {
  const bodyPackage = createLive2DPackage(coreReady);
  const options = engine === undefined
    ? {}
    : { live2dEngineFactory: (() => engine) as Live2DEngineFactory };
  return createBodyPresentationForTestCatalog(
    CONTROLLED_BODY_ID,
    createCatalog(bodyPackage),
    options,
  );
}

function createRuntimeHost(
  composition: ReturnType<typeof createCanonicalComposition>,
) {
  const coordinator = new BodyRenderCoordinator(composition.provider);
  const rendererHost = new BodyRendererHost(composition.renderer);
  return { coordinator, rendererHost };
}

async function flushMicrotasks(rounds = 20): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
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

describe("D21-D canonical body package authority", () => {
  it("derives binding kind and effective body from the same package authority", () => {
    const registeredPackage = resolveBodyPackage(DEFAULT_BODY_ID);
    const registeredBinding = resolveBodyBinding(DEFAULT_BODY_ID);
    const unknownPackage = resolveBodyPackage("unknown-body-id");
    const unknownBinding = resolveBodyBinding("unknown-body-id");

    expect(registeredBinding.presentationKind).toBe(
      registeredPackage.bodyPackage.presentation.kind,
    );
    expect(registeredBinding.effectiveBodyId).toBe(
      registeredPackage.effectiveBodyId,
    );
    expect(unknownBinding.presentationKind).toBe(
      unknownPackage.bodyPackage.presentation.kind,
    );
    expect(unknownBinding.effectiveBodyId).toBe(DEFAULT_BODY_ID);
    expect(unknownBinding.usedFallback).toBe(true);

    const bindingSource = readWorkspaceFile("src/body/bodyBinding.ts");
    expect(bindingSource).toContain("resolveBodyPackage(requestedBodyId)");
    expect(bindingSource).not.toMatch(/BODY_BINDING_CATALOG|new Map/);
  });

  it("uses exact opaque bodyId lookup in the controlled catalog", () => {
    const catalog = createCatalog();
    const exact = resolveBodyPackageForTestCatalog(
      CONTROLLED_BODY_ID,
      catalog,
    );
    const exactBinding = resolveBodyBindingForTestCatalog(
      CONTROLLED_BODY_ID,
      catalog,
    );
    const nearMiss = resolveBodyPackageForTestCatalog(
      `${CONTROLLED_BODY_ID}-suffix`,
      catalog,
    );
    const remote = resolveBodyPackageForTestCatalog(
      "https://example.invalid/evil.model3.json",
      catalog,
    );

    expect(exact).toMatchObject({
      requestedBodyId: CONTROLLED_BODY_ID,
      effectiveBodyId: CONTROLLED_BODY_ID,
      usedFallback: false,
    });
    expect(exact.bodyPackage.presentation.kind).toBe("live2d");
    expect(exactBinding).toMatchObject({
      effectiveBodyId: CONTROLLED_BODY_ID,
      usedFallback: false,
      presentationKind: exact.bodyPackage.presentation.kind,
    });
    expect(nearMiss.effectiveBodyId).toBe(DEFAULT_BODY_ID);
    expect(nearMiss.usedFallback).toBe(true);
    expect(remote.effectiveBodyId).toBe(DEFAULT_BODY_ID);
    expect(remote.usedFallback).toBe(true);
  });

  it("takes a controlled trusted Live2D package through the canonical factory", async () => {
    const engine = new ControlledLive2DEngine();
    const composition = createCanonicalComposition(engine);
    const { coordinator, rendererHost } = createRuntimeHost(composition);
    const host = document.createElement("div");

    expect(composition.provider).toBeInstanceOf(PngBodyProvider);
    const mount = rendererHost.mount(host);
    const render = coordinator.render("thinking").then((result) => {
      expect(result.applied).toBe(true);
      return rendererHost.render(result.snapshot);
    });

    await mount;
    await render;

    expect(engine.mountCalls).toBe(1);
    expect(engine.renderedSnapshots.map(({ state }) => state)).toEqual([
      "thinking",
    ]);
    expect(host.querySelector("[data-controlled-live2d=model]")).not.toBeNull();
    rendererHost.dispose();
    await flushMicrotasks();
  });

  it("revalidates a forged package source before renderer construction", () => {
    let coreCalls = 0;
    let factoryCalls = 0;
    const forgedPackage = {
      bodyId: CONTROLLED_BODY_ID,
      presentation: {
        kind: "live2d" as const,
        modelSource: {
          kind: "trusted-local-live2d-model" as const,
          path: "https://example.invalid/evil.model3.json",
        },
        coreReady: unavailableCore(() => {
          coreCalls += 1;
        }),
        fallbackResources: FALLBACK_RESOURCES,
      },
    };
    const compose = createPackagePresentationForDefinition as unknown as (
      definition: unknown,
      options?: { live2dEngineFactory?: Live2DEngineFactory },
    ) => unknown;

    expect(() =>
      compose(forgedPackage, {
        live2dEngineFactory: () => {
          factoryCalls += 1;
          throw new Error("renderer construction must not be reached");
        },
      }),
    ).toThrow(BodyRendererError);
    expect(coreCalls).toBe(0);
    expect(factoryCalls).toBe(0);
    expect(
      isTrustedLocalLive2DModelSource(forgedPackage.presentation.modelSource),
    ).toBe(false);
  });
});

describe("D21-D canonical lifecycle and failover", () => {
  it("waits for pending mount before first render and serializes host delivery", async () => {
    const pendingMount = new Deferred();
    const renderGate = new Deferred();
    const engine = new ControlledLive2DEngine({ pendingMount, renderGate });
    const composition = createCanonicalComposition(engine);
    const { coordinator, rendererHost } = createRuntimeHost(composition);
    const host = document.createElement("div");

    const mount = rendererHost.mount(host);
    const firstSnapshot = await coordinator.render("idle");
    const secondSnapshot = await coordinator.render("waiting");
    const first = rendererHost.render(firstSnapshot.snapshot);
    const second = rendererHost.render(secondSnapshot.snapshot);

    await flushMicrotasks();
    expect(engine.renderedSnapshots).toEqual([]);
    pendingMount.resolve();
    await mount;
    await flushMicrotasks();
    expect(engine.renderedSnapshots.map(({ state }) => state)).toEqual(["idle"]);

    renderGate.resolve();
    await first;
    await second;
    expect(engine.renderedSnapshots.map(({ state }) => state)).toEqual([
      "idle",
      "waiting",
    ]);
    rendererHost.dispose();
    await flushMicrotasks();
  });

  it("uses PNG through the canonical composition when Core is unavailable", async () => {
    let coreCalls = 0;
    const engine = new ControlledLive2DEngine();
    const composition = createCanonicalComposition(
      undefined,
      unavailableCore(() => {
        coreCalls += 1;
      }),
    );
    const { coordinator, rendererHost } = createRuntimeHost(composition);
    const host = document.createElement("div");
    const life = { bodyId: CONTROLLED_BODY_ID };

    await rendererHost.mount(host);
    for (const state of BODY_STATES) {
      const result = await coordinator.render(state);
      await rendererHost.render(result.snapshot);
      expect(result.snapshot).toEqual(snapshotFor(state));
      expect(host.querySelector("img")?.getAttribute("src")).toBe(
        result.snapshot.resourcePath,
      );
      expect(host.querySelector("img")?.getAttribute("alt")).toBe(
        `Digital Life ${state} body`,
      );
    }

    expect(coreCalls).toBe(1);
    expect(engine.mountCalls).toBe(0);
    expect(life.bodyId).toBe(CONTROLLED_BODY_ID);
    rendererHost.dispose();
    await flushMicrotasks();
  });

  it("retires a primary whose mount fails and preserves the exact snapshot in PNG", async () => {
    const engine = new ControlledLive2DEngine({ failMount: true });
    const composition = createCanonicalComposition(engine);
    const { coordinator, rendererHost } = createRuntimeHost(composition);
    const host = document.createElement("div");

    await rendererHost.mount(host);
    const first = await coordinator.render("speaking");
    await rendererHost.render(first.snapshot);
    const second = await coordinator.render("error");
    await rendererHost.render(second.snapshot);

    expect(host.querySelector("img")?.getAttribute("src")).toBe(
      second.snapshot.resourcePath,
    );
    expect(second.snapshot.state).toBe("error");
    expect(engine.mountCalls).toBe(1);
    expect(engine.disposeCalls).toBe(1);
    rendererHost.dispose();
    await flushMicrotasks();
  });

  it("retires a primary whose render fails and preserves all five states in PNG", async () => {
    const engine = new ControlledLive2DEngine({ failRender: true });
    const composition = createCanonicalComposition(engine);
    const { coordinator, rendererHost } = createRuntimeHost(composition);
    const host = document.createElement("div");

    await rendererHost.mount(host);
    for (const state of BODY_STATES) {
      const result = await coordinator.render(state);
      await rendererHost.render(result.snapshot);
      expect(result.snapshot.state).toBe(state);
      expect(host.querySelector("img")?.getAttribute("src")).toBe(
        result.snapshot.resourcePath,
      );
    }

    expect(engine.mountCalls).toBe(1);
    expect(engine.disposeCalls).toBe(1);
    expect(engine.renderedSnapshots.map(({ state }) => state)).toEqual(["idle"]);
    rendererHost.dispose();
    await flushMicrotasks();
  });

  it("does not resurrect a canvas or model after dispose during pending mount", async () => {
    const pendingMount = new Deferred();
    const engine = new ControlledLive2DEngine({ pendingMount });
    const composition = createCanonicalComposition(engine);
    const { coordinator, rendererHost } = createRuntimeHost(composition);
    const host = document.createElement("div");

    const mount = rendererHost.mount(host);
    const render = coordinator.render("thinking").then((result) =>
      rendererHost.render(result.snapshot),
    );
    await flushMicrotasks();
    rendererHost.dispose();
    rendererHost.dispose();
    pendingMount.resolve();

    await expect(mount).resolves.toBeUndefined();
    await expect(render).rejects.toBeInstanceOf(BodyRendererError);
    await flushMicrotasks(30);

    expect(engine.modelCreated).toBe(1);
    expect(engine.modelDestroyed).toBe(1);
    expect(engine.disposeCalls).toBe(1);
    expect(engine.renderedSnapshots).toEqual([]);
    expect(host.childElementCount).toBe(0);
  });

  it("fences a late Main-WebView-style lifecycle continuation", async () => {
    const pendingMount = new Deferred();
    const engine = new ControlledLive2DEngine({ pendingMount });
    const composition = createCanonicalComposition(engine);
    const { coordinator, rendererHost } = createRuntimeHost(composition);
    const host = document.createElement("div");
    let lifecycleEpoch = 1;
    const runtimeEpoch = lifecycleEpoch;

    const mount = rendererHost.mount(host);
    const continuation = coordinator.render("thinking").then((result) => {
      if (lifecycleEpoch !== runtimeEpoch || !result.applied) {
        return;
      }
      return rendererHost.render(result.snapshot);
    });

    lifecycleEpoch += 1;
    rendererHost.dispose();
    pendingMount.resolve();
    await mount;
    await continuation;
    await flushMicrotasks(30);

    expect(engine.renderedSnapshots).toEqual([]);
    expect(host.childElementCount).toBe(0);
  });
});

describe("D21-D production ownership and honest asset boundary", () => {
  it("keeps the default fallback and App runtime binding authority", () => {
    const defaultPackage = resolveBodyPackage(DEFAULT_BODY_ID);
    expect(defaultPackage.bodyPackage.presentation.kind).toBe("png");
    expect(resolveBodyBinding("unknown-body")).toMatchObject({
      effectiveBodyId: DEFAULT_BODY_ID,
      usedFallback: true,
      presentationKind: "png",
    });
    expect(createBodyPresentationForBodyId("unknown-body").provider).toBeDefined();

    const appSource = readWorkspaceFile("src/App.vue");
    expect(appSource).toContain("BodyRuntimeBindingController");
    expect(appSource).toContain("createBodyPresentationForBodyId(bodyId)");
    expect(appSource).not.toMatch(/new Live2DRenderer|createLive2DCoreReadyBoundary|Pixi|Cubism|model3/i);
    for (const source of [
      ...sourceFilesUnder("src/chat"),
      ...sourceFilesUnder("src/settings").filter(
        (value) => !value.includes("Import Live2D body"),
      ),
    ]) {
      expect(source).not.toMatch(/Live2D|live2d|Pixi|Cubism|BodyRendererHost/i);
    }
  });

  it("keeps production Core/model source free of remote bootstrap and samples", () => {
    // D22-D1: managedCubismCore.ts is the one sanctioned script-injection
    // seam; every other production body module stays free of remote
    // bootstrap and Core script references.
    const productionSource = sourceFilesUnder(
      "src/body",
      (name) => name === "managedCubismCore.ts",
    ).join("\n");
    expect(productionSource).not.toMatch(
      /https:\/\/cubism\.live2d\.com|live2dcubismcore\.min\.js|script\.src\s*=|append\(\s*script\s*\)/i,
    );
    expect(productionSource).not.toMatch(/Haru|Mark|Rice/i);
  });

  it("keeps package composition renderer-neutral at the public barrel", () => {
    const indexSource = readWorkspaceFile("src/body/index.ts");
    const packageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    expect(indexSource).not.toMatch(
      /createPackagePresentation|BodyPackageDefinition|from\s+["']\.\/live2d/i,
    );
    expect(packageSource).toContain("requireTrustedLive2DModelUrl(modelSource)");
    expect(packageSource).toContain("new Live2DRenderer(");
    expect(packageSource.indexOf("requireTrustedLive2DModelUrl(modelSource)")).toBeLessThan(
      packageSource.indexOf("new Live2DRenderer("),
    );
  });

  it("keeps the D21-C private source brand and local-only validator", () => {
    const source = readWorkspaceFile("src/body/live2dModelSource.ts");
    expect(source).toContain("unique symbol");
    expect(source).toContain("createTrustedLocalLive2DModelSource");
    expect(source).toContain("isTrustedLocalLive2DModelSource");
    expect(source).toContain("model3.json");
    expect(source).not.toMatch(/export\s+(const|let|var)\s+trustedLocalLive2DModelSourceBrand/);
  });
});

describe("D21-D type compatibility", () => {
  it("keeps the renderer contract available without exposing a second package API", () => {
    const renderer: BodyRenderer = {
      mount: async () => undefined,
      render: async () => undefined,
      dispose: async () => undefined,
    };

    expect(renderer).toBeDefined();
  });
});
