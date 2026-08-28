import fs from "node:fs";
import path from "node:path";

import { describe, expect, it } from "vitest";

import {
  BODY_STATES,
  DEFAULT_BODY_ID,
  FallbackBodyRenderer,
  PngBodyProvider,
  PngBodyRenderer,
  createBodyPresentationForBodyId,
  resolveBodyBinding,
} from "../src/body";
import { BodyRendererError } from "../src/body/bodyRenderer";
import {
  createPackagePresentationForDefinition,
} from "../src/body/bodyPackage";
import {
  createTrustedLocalLive2DModelSource,
  isTrustedLocalLive2DModelPath,
} from "../src/body/live2dModelSource";
import { Live2DCoreUnavailableError } from "../src/body/live2dRenderer";
import type { Live2DCoreReadyBoundary } from "../src/body/live2dRuntime";
import type { BodyRenderer } from "../src/body/bodyRenderer";
import type { BodySnapshot } from "../src/body/types";

const LOCAL_MODEL_PATH = "/bundled-body/test/test.model3.json";

function readWorkspaceFile(relativePath: string): string {
  return fs.readFileSync(path.resolve(process.cwd(), relativePath), "utf8");
}

function sourceFilesUnder(relativePath: string): string[] {
  const root = path.resolve(process.cwd(), relativePath);
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

function snapshotFor(state: (typeof BODY_STATES)[number]): BodySnapshot {
  return {
    resourcePath: `/package-fallback/${state}.png`,
    state,
  };
}

function createUnavailableCoreBoundary(
  onEnsureReady?: () => void,
): Live2DCoreReadyBoundary {
  return {
    ensureReady(): never {
      onEnsureReady?.();
      throw new Live2DCoreUnavailableError();
    },
  };
}

function createLive2DPackage(
  coreReady: Live2DCoreReadyBoundary = createUnavailableCoreBoundary(),
) {
  return Object.freeze({
    bodyId: "test-local-live2d",
    presentation: Object.freeze({
      kind: "live2d" as const,
      modelSource: createTrustedLocalLive2DModelSource(LOCAL_MODEL_PATH),
      coreReady,
      fallbackResources: Object.freeze({
        idle: "/package-fallback/idle.png",
        thinking: "/package-fallback/thinking.png",
        speaking: "/package-fallback/speaking.png",
        waiting: "/package-fallback/waiting.png",
        error: "/package-fallback/error.png",
      }),
    }),
  });
}

describe("D21-C trusted local model-source boundary", () => {
  it("accepts only an immutable packaged local model descriptor", () => {
    const source = createTrustedLocalLive2DModelSource(LOCAL_MODEL_PATH);

    expect(source).toEqual({
      kind: "trusted-local-live2d-model",
      path: LOCAL_MODEL_PATH,
    });
    expect(Object.isFrozen(source)).toBe(true);
    expect(isTrustedLocalLive2DModelPath(LOCAL_MODEL_PATH)).toBe(true);
  });

  it.each([
    "http://example.test/model.model3.json",
    "https://example.test/model.model3.json",
    "//example.test/model.model3.json",
    "data:application/json,{}",
    "javascript:alert(1)",
    "file:///C:/models/model.model3.json",
    "../model.model3.json",
    "C:/models/model.model3.json",
  ])("rejects non-local model source %s", (modelPath) => {
    expect(isTrustedLocalLive2DModelPath(modelPath)).toBe(false);
    expect(() => createTrustedLocalLive2DModelSource(modelPath)).toThrow(
      BodyRendererError,
    );
  });

  it("keeps model source package-configured and independent from bodyId/state", () => {
    const packageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    const modelSource = readWorkspaceFile("src/body/live2dModelSource.ts");

    expect(packageSource).toContain("modelSource.path");
    expect(packageSource).not.toMatch(/snapshot|resourcePath|user|bodyId.*path/i);
    expect(modelSource).toContain("^[a-z][a-z0-9+.-]*:");
    expect(modelSource).toContain("model3.json");
  });
});

describe("D21-C closed presentation and package contract", () => {
  it("keeps BodyPresentationKind closed to exactly png and live2d", () => {
    const bindingSource = readWorkspaceFile("src/body/bodyBinding.ts");

    expect(bindingSource).toMatch(
      /export type BodyPresentationKind = "png" \| "live2d";/,
    );
  });

  it("keeps package definitions internal while exposing a focused definition seam", () => {
    const packageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    const indexSource = readWorkspaceFile("src/body/index.ts");

    expect(packageSource).toMatch(/interface PngBodyPackage/);
    expect(packageSource).toMatch(/interface Live2DBodyPackage/);
    expect(packageSource).toMatch(/type BodyPackageDefinition =/);
    expect(packageSource).toContain("createPackagePresentationForDefinition");
    expect(indexSource).not.toMatch(/createPackagePresentationForDefinition/);
    expect(indexSource).not.toMatch(/from\s+["']\.\/live2d|createLive2D|new\s+Live2D/i);
  });

  it("composes the PNG provider with Live2D primary and PNG fallback renderers", () => {
    const packageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    const composition = createPackagePresentationForDefinition(
      createLive2DPackage(),
    );

    expect(composition.provider).toBeInstanceOf(PngBodyProvider);
    expect(composition.renderer).toBeInstanceOf(FallbackBodyRenderer);
    expect(packageSource).toMatch(/new Live2DRenderer\(/);
    expect(packageSource).toMatch(/new PngBodyProvider\(fallbackResources\)/);
    expect(packageSource).toMatch(
      /new FallbackBodyRenderer\(\s*live2dRenderer,\s*new PngBodyRenderer\(\),/s,
    );
  });

  it("injects the package Core-ready boundary into the Live2D renderer", async () => {
    let ensureCalls = 0;
    const composition = createPackagePresentationForDefinition(
      createLive2DPackage(
        createUnavailableCoreBoundary(() => {
          ensureCalls += 1;
        }),
      ),
    );
    const host = document.createElement("div");

    await composition.renderer.mount(host);
    expect(ensureCalls).toBe(1);
    await composition.renderer.dispose();
  });

  it("uses PNG fallback when Core is unavailable without changing the snapshot", async () => {
    const composition = createPackagePresentationForDefinition(
      createLive2DPackage(),
    );
    const snapshot = snapshotFor("thinking");
    const host = document.createElement("div");

    await composition.renderer.mount(host);
    await composition.renderer.render(snapshot);

    const image = host.querySelector("img");
    expect(image?.getAttribute("src")).toBe(snapshot.resourcePath);
    expect(image?.getAttribute("alt")).toBe("Digital Life thinking body");
    await composition.renderer.dispose();
  });

  it("uses PNG fallback when the primary model mount fails", async () => {
    const primary: BodyRenderer = {
      mount: async () => {
        throw new BodyRendererError("controlled model mount failure");
      },
      render: async () => undefined,
      dispose: async () => undefined,
    };
    const fallback = new PngBodyRenderer();
    const renderer = new FallbackBodyRenderer(primary, fallback);
    const snapshot = snapshotFor("error");
    const host = document.createElement("div");

    await renderer.mount(host);
    await renderer.render(snapshot);

    expect(host.querySelector("img")?.getAttribute("src")).toBe(
      snapshot.resourcePath,
    );
    await renderer.dispose();
  });

  it("preserves every frozen BodyState across Live2D-to-PNG failover", async () => {
    const composition = createPackagePresentationForDefinition(
      createLive2DPackage(),
    );
    const host = document.createElement("div");

    await composition.renderer.mount(host);
    for (const state of BODY_STATES) {
      const snapshot = await composition.provider.switchState(state);
      await composition.renderer.render(snapshot);
      expect(host.querySelector("img")?.getAttribute("src")).toBe(
        snapshot.resourcePath,
      );
      expect(host.querySelector("img")?.getAttribute("alt")).toBe(
        `Digital Life ${state} body`,
      );
    }
    await composition.renderer.dispose();
  });
});

describe("D21-C production activation and authority gates", () => {
  it("does not register a fabricated Live2D production package", () => {
    expect(resolveBodyBinding("test-local-live2d")).toEqual({
      requestedBodyId: "test-local-live2d",
      effectiveBodyId: DEFAULT_BODY_ID,
      usedFallback: true,
      presentationKind: "png",
    });
    expect(resolveBodyBinding("live2d:/bundled-body/test/test.model3.json")).toEqual({
      requestedBodyId: "live2d:/bundled-body/test/test.model3.json",
      effectiveBodyId: DEFAULT_BODY_ID,
      usedFallback: true,
      presentationKind: "png",
    });
  });

  it("keeps default-png as the real production package and preserves its states", async () => {
    const composition = createBodyPresentationForBodyId(DEFAULT_BODY_ID);

    expect(resolveBodyBinding(DEFAULT_BODY_ID).presentationKind).toBe("png");
    for (const state of BODY_STATES) {
      const snapshot = await composition.provider.switchState(state);
      expect(snapshot.state).toBe(state);
      expect(snapshot.resourcePath.length).toBeGreaterThan(0);
    }
    await composition.renderer.dispose();
  });

  it("keeps App, chat, and settings renderer-neutral", () => {
    expect(readWorkspaceFile("src/App.vue")).not.toMatch(/Live2D|live2d/i);
    for (const source of [
      ...sourceFilesUnder("src/chat"),
      ...sourceFilesUnder("src/settings"),
    ]) {
      expect(source).not.toMatch(/Live2D|live2d|BodyRenderer|BodyRendererHost/i);
    }
  });

  it("keeps remote Core bootstrap and sample model names out of production source", () => {
    const productionSource = sourceFilesUnder("src/body").join("\n");

    expect(productionSource).not.toMatch(
      /https:\/\/cubism\.live2d\.com|live2dcubismcore\.min\.js|script\.src\s*=|append\(\s*script\s*\)/i,
    );
    expect(productionSource).not.toMatch(/Haru|Mark|Rice/i);
  });

  it("keeps the canonical bodyId composition path and no dynamic asset lookup", () => {
    const bindingSource = readWorkspaceFile("src/body/bodyBinding.ts");
    const packageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    const appSource = readWorkspaceFile("src/App.vue");

    expect(appSource).toContain("createBodyPresentationForBodyId(life.bodyId)");
    expect(bindingSource).toContain("BODY_BINDING_CATALOG.get(requestedBodyId)");
    expect(bindingSource).not.toMatch(/startsWith|includes|prefix|fuzzy|live2d:/i);
    expect(packageSource).not.toMatch(/import\s*\(|dynamic|bodyId.*(?:path|url)/i);
  });
});
