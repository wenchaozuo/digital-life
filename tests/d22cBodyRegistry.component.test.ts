import fs from "node:fs";
import path from "node:path";

import { afterEach, describe, expect, expectTypeOf, it } from "vitest";

import {
  BODY_BINDING_CHANGED_EVENT,
  BodyBindingChangedListenerLifecycle,
  DEFAULT_BODY_ID,
  FallbackBodyRenderer,
  installManagedBodyPackageRegistrySnapshot,
  createBodyBindingChangedBridge,
  isBodyBindingChangedEvent,
  resolveBodyBinding,
} from "../src/body";
import {
  createPackagePresentationForDefinition,
  resetManagedLive2DModelPackageRegistryForTest,
} from "../src/body/bodyPackage";
import {
  createTrustedManagedLive2DModelSource,
  isTrustedManagedLive2DModelSource,
} from "../src/body/live2dModelSource";
import { BodyRendererError } from "../src/body/bodyRenderer";
import { Live2DCoreUnavailableError } from "../src/body/live2dRenderer";
import type { Live2DCoreReadyBoundary } from "../src/body/live2dRuntime";
import type { InstalledBodyPackageSnapshot } from "../src/body/bodyPackageService";
import type { TrustedManagedLive2DModelSource } from "../src/body/live2dModelSource";

const BODY_ID = "live2d-deadbeef";
const WINDOWS_MODEL_ENTRY =
  "http://digital-life-body.localhost/live2d-deadbeef/avatar.model3.json";
const LINUX_MODEL_ENTRY =
  "digital-life-body://localhost/live2d-deadbeef/avatar.model3.json";

function snapshot(
  modelEntry = WINDOWS_MODEL_ENTRY,
  status: InstalledBodyPackageSnapshot["status"] = "available",
  bodyId = BODY_ID,
): InstalledBodyPackageSnapshot {
  return {
    bodyId,
    displayName: "Managed body",
    presentationKind: "live2d",
    modelEntry,
    packageContentHash: "hash",
    packageVersion: 1,
    installedAt: "2026-08-29T00:00:00.000Z",
    status,
    assets: [],
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

function composeUnknown(value: unknown) {
  const compose = createPackagePresentationForDefinition as unknown as (
    definition: unknown,
  ) => ReturnType<typeof createPackagePresentationForDefinition>;
  return compose(value);
}

function forgedPackage(modelEntry: string, onEnsureReady: () => void) {
  return {
    bodyId: "forged-live2d",
    presentation: {
      kind: "live2d" as const,
      modelSource: {
        kind: "trusted-managed-live2d-model" as const,
        bodyId: BODY_ID,
        url: modelEntry,
      },
      coreReady: unavailableCore(onEnsureReady),
      fallbackResources: {
        idle: "/fallback/idle.png",
        thinking: "/fallback/thinking.png",
        speaking: "/fallback/speaking.png",
        waiting: "/fallback/waiting.png",
        error: "/fallback/error.png",
      },
    },
  };
}

afterEach(() => {
  resetManagedLive2DModelPackageRegistryForTest();
});

describe("D22-C managed model-source authority", () => {
  it("accepts only factory-created immutable sources from paired snapshot fields", () => {
    const source = createTrustedManagedLive2DModelSource({
      bodyId: BODY_ID,
      modelEntry: WINDOWS_MODEL_ENTRY,
    });

    expect(source).toMatchObject({
      kind: "trusted-managed-live2d-model",
      bodyId: BODY_ID,
      url: WINDOWS_MODEL_ENTRY,
    });
    expect(Object.getOwnPropertySymbols(source)).toHaveLength(1);
    expect(Object.isFrozen(source)).toBe(true);
    expect(isTrustedManagedLive2DModelSource(source)).toBe(true);

    const structurallySimilar = {
      kind: "trusted-managed-live2d-model" as const,
      bodyId: BODY_ID,
      url: WINDOWS_MODEL_ENTRY,
    };
    expectTypeOf(structurallySimilar).not.toMatchTypeOf<
      TrustedManagedLive2DModelSource
    >();
    expect(isTrustedManagedLive2DModelSource(structurallySimilar)).toBe(false);
  });

  it.each([
    "https://example.invalid/evil.model3.json",
    "http://example.invalid/evil.model3.json",
    "file:///C:/evil.model3.json",
    "data:application/json,{}",
    "javascript:alert(1)",
    "//example.invalid/evil.model3.json",
  ])("rejects direct remote or non-managed model entries: %s", (modelEntry) => {
    expect(() =>
      createTrustedManagedLive2DModelSource({ bodyId: BODY_ID, modelEntry }),
    ).toThrow(BodyRendererError);
  });

  it.each([
    "http://digital-life-body.localhost:443/live2d-deadbeef/avatar.model3.json",
    "http://digital-life-body.localhost.evil/live2d-deadbeef/avatar.model3.json",
    "https://digital-life-body.localhost/live2d-deadbeef/avatar.model3.json",
    "digital-life-body://evil/live2d-deadbeef/avatar.model3.json",
    "digital-life-body://localhost:443/live2d-deadbeef/avatar.model3.json",
    "http://digital-life-body.localhost/live2d-deadbeef/../evil.model3.json",
    "http://digital-life-body.localhost/live2d-deadbeef/%2e%2e/evil.model3.json",
    "http://digital-life-body.localhost/live2d-deadbeef/avatar.model3.json?x=1",
    "http://digital-life-body.localhost/live2d-deadbeef/avatar.model3.json#x",
    "http://digital-life-body.localhost/live2d-deadbeef/avatar%5c.model3.json",
    "http://digital-life-body.localhost/live2d-cafebabe/avatar.model3.json",
  ])("rejects malformed managed URL authority or path: %s", (modelEntry) => {
    expect(() =>
      createTrustedManagedLive2DModelSource({ bodyId: BODY_ID, modelEntry }),
    ).toThrow(BodyRendererError);
  });

  it("accepts the Windows and macOS/Linux backend URL policies", () => {
    expect(
      isTrustedManagedLive2DModelSource(
        createTrustedManagedLive2DModelSource({
          bodyId: BODY_ID,
          modelEntry: WINDOWS_MODEL_ENTRY,
        }),
      ),
    ).toBe(true);
    expect(
      isTrustedManagedLive2DModelSource(
        createTrustedManagedLive2DModelSource({
          bodyId: BODY_ID,
          modelEntry: LINUX_MODEL_ENTRY,
        }),
      ),
    ).toBe(true);
  });

  it("accepts backend percent-encoded model path components", () => {
    const source = createTrustedManagedLive2DModelSource({
      bodyId: BODY_ID,
      modelEntry:
        "http://digital-life-body.localhost/live2d-deadbeef/face%20one.model3.json",
    });
    expect(isTrustedManagedLive2DModelSource(source)).toBe(true);
  });

  it.each([
    "https://example.invalid/evil.model3.json",
    "http://example.invalid/evil.model3.json",
    "file:///C:/evil.model3.json",
    "data:application/json,{}",
    "javascript:alert(1)",
    "//example.invalid/evil.model3.json",
  ])("rejects forged package source before Core readiness: %s", (modelEntry) => {
    let coreCalls = 0;
    expect(() => composeUnknown(forgedPackage(modelEntry, () => coreCalls++))).toThrow(
      BodyRendererError,
    );
    expect(coreCalls).toBe(0);
  });

  it("revalidates a valid managed source and preserves Core-absent PNG fallback", async () => {
    const source = createTrustedManagedLive2DModelSource({
      bodyId: BODY_ID,
      modelEntry: WINDOWS_MODEL_ENTRY,
    });
    const composition = createPackagePresentationForDefinition({
      bodyId: BODY_ID,
      presentation: {
        kind: "live2d",
        modelSource: source,
        coreReady: unavailableCore(),
        fallbackResources: {
          idle: "/fallback/idle.png",
          thinking: "/fallback/thinking.png",
          speaking: "/fallback/speaking.png",
          waiting: "/fallback/waiting.png",
          error: "/fallback/error.png",
        },
      },
    });
    expect(composition.renderer).toBeInstanceOf(FallbackBodyRenderer);
    const host = document.createElement("div");
    await composition.renderer.mount(host);
    const rendered = await composition.provider.switchState("thinking");
    await composition.renderer.render(rendered);
    expect(host.querySelector("img")).not.toBeNull();
    expect(host.querySelector("img")?.getAttribute("src")).toBe(
      rendered.resourcePath,
    );
    await composition.renderer.dispose();
  });
});

describe("D22-C process-local managed body registry", () => {
  it("keeps default-png authoritative, installs available entries, and excludes corrupt entries", () => {
    expect(resolveBodyBinding(DEFAULT_BODY_ID).presentationKind).toBe("png");
    installManagedBodyPackageRegistrySnapshot([
      snapshot(),
      snapshot(LINUX_MODEL_ENTRY, "corrupt-unavailable", "live2d-c0ffee"),
    ]);

    expect(resolveBodyBinding(BODY_ID)).toEqual({
      requestedBodyId: BODY_ID,
      effectiveBodyId: BODY_ID,
      usedFallback: false,
      presentationKind: "live2d",
    });
    expect(resolveBodyBinding("live2d-corrupt").usedFallback).toBe(true);
  });

  it("replaces the registry atomically and rejects duplicate/default collisions", () => {
    installManagedBodyPackageRegistrySnapshot([snapshot()]);
    expect(resolveBodyBinding(BODY_ID).usedFallback).toBe(false);

    expect(() =>
      installManagedBodyPackageRegistrySnapshot([
        snapshot(),
        { ...snapshot(), displayName: "duplicate" },
      ]),
    ).toThrow(BodyRendererError);
    expect(resolveBodyBinding(BODY_ID).usedFallback).toBe(false);

    expect(() =>
      installManagedBodyPackageRegistrySnapshot([
        snapshot(),
        { ...snapshot(), modelEntry: "https://example.invalid/evil.model3.json" },
      ]),
    ).toThrow(BodyRendererError);
    expect(resolveBodyBinding(BODY_ID).usedFallback).toBe(false);

    expect(() =>
      installManagedBodyPackageRegistrySnapshot([
        { ...snapshot(), bodyId: DEFAULT_BODY_ID },
      ]),
    ).toThrow(BodyRendererError);
    expect(resolveBodyBinding(BODY_ID).usedFallback).toBe(false);
  });

  it("uses exact prototype-safe resolution and retains unknown-body fallback", () => {
    installManagedBodyPackageRegistrySnapshot([snapshot()]);
    expect(resolveBodyBinding("__proto__")).toEqual({
      requestedBodyId: "__proto__",
      effectiveBodyId: DEFAULT_BODY_ID,
      usedFallback: true,
      presentationKind: "png",
    });
    expect(resolveBodyBinding("unknown-body").effectiveBodyId).toBe(DEFAULT_BODY_ID);
  });

  it("keeps App as a renderer-owner controller and Settings without renderer construction", () => {
    const appSource = fs.readFileSync(
      path.join(process.cwd(), "src/App.vue"),
      "utf8",
    );
    const settingsSource = fs.readFileSync(
      path.join(process.cwd(), "src/settings/body/BodySettingsView.vue"),
      "utf8",
    );
    const mainCommands = fs.readFileSync(
      path.join(process.cwd(), "src-tauri/permissions/main-commands.toml"),
      "utf8",
    );

    expect(appSource).toContain("BodyRuntimeBindingController");
    expect(appSource).toContain("createBodyPresentationForBodyId");
    expect(appSource).not.toContain("new Live2DRenderer");
    expect(settingsSource).not.toMatch(/BodyRenderer|BodyRendererHost|Live2DRenderer/);
    expect(settingsSource).not.toMatch(/<canvas|renderer\.mount|createBodyPresentation/);
    expect(mainCommands).toContain('"get_body_package_registry_snapshot"');
    expect(mainCommands).not.toContain('"set_current_life_body"');
  });
});

describe("D22-C body-binding refresh hint", () => {
  it("accepts only bounded metadata and excludes body/path authority", () => {
    expect(BODY_BINDING_CHANGED_EVENT).toBe(
      "digital-life://body-binding-changed/v1",
    );
    expect(
      isBodyBindingChangedEvent({
        version: 1,
        lifeId: "life-1",
        lifeVersion: 3,
      }),
    ).toBe(true);
    expect(
      isBodyBindingChangedEvent({
        version: 1,
        lifeId: "life-1",
        lifeVersion: 3,
        bodyId: BODY_ID,
      }),
    ).toBe(false);
    expect(
      isBodyBindingChangedEvent({
        version: 2,
        lifeId: "life-1",
        lifeVersion: 3,
      }),
    ).toBe(false);
  });

  it("filters malformed transport payloads and fences late unlisten", async () => {
    let received = 0;
    let transportHandler: ((payload: unknown) => void) | undefined;
    const bridge = createBodyBindingChangedBridge({
      async subscribe(handler) {
        transportHandler = handler;
        return () => undefined;
      },
    });
    await bridge.listen(() => {
      received += 1;
    });
    transportHandler?.({ version: 1, lifeId: "life-1", lifeVersion: 1 });
    transportHandler?.({ version: 1, lifeId: "life-1", lifeVersion: 1 });
    transportHandler?.({ version: 1, lifeId: "life-1", lifeVersion: 1, bodyId: BODY_ID });
    expect(received).toBe(2);

    let resolveRegistration: ((unlisten: () => void) => void) | undefined;
    const registration = new Promise<() => void>((resolve) => {
      resolveRegistration = resolve;
    });
    let unlistenCalls = 0;
    const lifecycle = new BodyBindingChangedListenerLifecycle(() => registration);
    lifecycle.start(() => undefined);
    lifecycle.stop();
    resolveRegistration?.(() => {
      unlistenCalls += 1;
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(unlistenCalls).toBe(1);
  });
});
