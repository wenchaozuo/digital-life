import fs from "node:fs";
import path from "node:path";

import { describe, expect, expectTypeOf, it } from "vitest";

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
  isTrustedLocalLive2DModelSource,
} from "../src/body/live2dModelSource";
import { Live2DCoreUnavailableError } from "../src/body/live2dRenderer";
import type { Live2DCoreReadyBoundary } from "../src/body/live2dRuntime";
import type { BodyRenderer } from "../src/body/bodyRenderer";
import type { BodySnapshot } from "../src/body/types";
import type { TrustedLocalLive2DModelSource } from "../src/body/live2dModelSource";

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

function composeRuntimePackage(value: unknown) {
  // This cast models an untyped runtime boundary in the test. Production
  // callers still see the branded BodyPackageDefinition parameter.
  const compose = createPackagePresentationForDefinition as unknown as (
    definition: unknown,
  ) => ReturnType<typeof createPackagePresentationForDefinition>;
  return compose(value);
}

function createForgedLive2DPackage(
  modelPath: string,
  onEnsureReady?: () => void,
) {
  return {
    bodyId: "forged-live2d",
    presentation: {
      kind: "live2d" as const,
      modelSource: {
        kind: "trusted-local-live2d-model" as const,
        path: modelPath,
      },
      coreReady: createUnavailableCoreBoundary(onEnsureReady),
      fallbackResources: {
        idle: "/package-fallback/idle.png",
        thinking: "/package-fallback/thinking.png",
        speaking: "/package-fallback/speaking.png",
        waiting: "/package-fallback/waiting.png",
        error: "/package-fallback/error.png",
      },
    },
  };
}

describe("D21-C trusted local model-source boundary", () => {
  it("accepts only an immutable packaged local model descriptor", () => {
    const source = createTrustedLocalLive2DModelSource(LOCAL_MODEL_PATH);

    expect(source.kind).toBe("trusted-local-live2d-model");
    expect(source.path).toBe(LOCAL_MODEL_PATH);
    expect(Object.keys(source)).toEqual(["kind", "path"]);
    expect(Object.getOwnPropertySymbols(source)).toHaveLength(1);
    expect(Object.isFrozen(source)).toBe(true);
    expect(isTrustedLocalLive2DModelPath(LOCAL_MODEL_PATH)).toBe(true);
    expect(isTrustedLocalLive2DModelSource(source)).toBe(true);
  });

  it("does not let an ordinary object literal satisfy the branded source type", () => {
    const structurallySimilarSource = {
      kind: "trusted-local-live2d-model" as const,
      path: LOCAL_MODEL_PATH,
    };

    expectTypeOf(structurallySimilarSource).not.toMatchTypeOf<
      TrustedLocalLive2DModelSource
    >();
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

  it("keeps managed and local model sources inside the package authority", () => {
    const packageSource = readWorkspaceFile("src/body/bodyPackage.ts");
    const modelSource = readWorkspaceFile("src/body/live2dModelSource.ts");

    expect(packageSource).toContain(
      "requireTrustedLive2DModelUrl(modelSource)",
    );
    expect(packageSource).not.toContain("modelSource.path");
    expect(packageSource).toContain("createTrustedManagedLive2DModelSource");
    expect(packageSource).not.toMatch(/resourcePath|user|modelSource\.path/i);
    expect(modelSource).toContain("^[a-z][a-z0-9+.-]*:");
    expect(modelSource).toContain("model3.json");
  });

  it.each([
    "http://example.invalid/evil.model3.json",
    "https://example.invalid/evil.model3.json",
    "file:///C:/evil.model3.json",
    "data:application/json,{}",
    "javascript:alert(1)",
    "//example.invalid/evil.model3.json",
  ])("rejects a forged package source before Core readiness: %s", (modelPath) => {
    let coreCalls = 0;
    const forgedPackage = createForgedLive2DPackage(modelPath, () => {
      coreCalls += 1;
    });

    expect(() => composeRuntimePackage(forgedPackage)).toThrow(BodyRendererError);
    expect(coreCalls).toBe(0);
    expect(isTrustedLocalLive2DModelSource(forgedPackage.presentation.modelSource)).toBe(
      false,
    );
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
    expect(
      packageSource.indexOf("requireTrustedLive2DModelUrl(modelSource)"),
    ).toBeLessThan(packageSource.indexOf("new Live2DRenderer("));
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

  it("keeps App as the renderer owner and chat/settings free of renderer construction", () => {
    expect(readWorkspaceFile("src/App.vue")).toMatch(/BodyRuntimeBindingController/);
    expect(readWorkspaceFile("src/App.vue")).not.toMatch(/new Live2DRenderer|createLive2DCoreReadyBoundary/);
    for (const source of [
      ...sourceFilesUnder("src/chat"),
      ...sourceFilesUnder("src/settings"),
    ]) {
      expect(source).not.toMatch(/new Live2DRenderer|createLive2DCoreReadyBoundary|BodyRendererHost|<canvas/i);
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

    expect(appSource).toContain(
      "createPresentation: (bodyId) => createBodyPresentationForBodyId(bodyId)",
    );
    expect(bindingSource).toContain("resolveBodyPackage(requestedBodyId)");
    expect(bindingSource).not.toMatch(/BODY_BINDING_CATALOG|new Map/);
    expect(packageSource).toContain("BODY_PACKAGE_CATALOG");
    expect(bindingSource).not.toMatch(/startsWith|includes|prefix|fuzzy|live2d:/i);
    expect(packageSource).not.toMatch(/import\s*\(|dynamic|bodyId.*(?:path|url)/i);
  });
});
