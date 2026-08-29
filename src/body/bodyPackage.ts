import { BodyRendererError } from "./bodyRenderer.ts";
import { FallbackBodyRenderer } from "./fallbackBodyRenderer.ts";
import { FallbackBodyProvider } from "./fallbackBodyProvider.ts";
import { Live2DRenderer } from "./live2dRenderer.ts";
import { PngBodyRenderer } from "./pngBodyRenderer.ts";
import { PngBodyProvider } from "./pngBodyProvider.ts";
import {
  DEFAULT_BUNDLED_PNG_RESOURCES,
  type PngBodyResources,
} from "./pngBodyResources.ts";
import type {
  Live2DCoreReadyBoundary,
  Live2DEngineFactory,
} from "./live2dRuntime.ts";
import {
  createTrustedManagedLive2DModelSource,
  requireTrustedLive2DModelUrl,
  type TrustedManagedLive2DModelSource,
  type TrustedLocalLive2DModelSource,
} from "./live2dModelSource.ts";
import { createLive2DCoreReadyBoundary } from "./live2dRuntime.ts";
import type { InstalledBodyPackageSnapshot } from "./bodyPackageService.ts";
import type { BodyPresentationComposition } from "./bodyBinding.ts";

export const DEFAULT_BODY_ID = "default-png";

interface PngBodyPackage {
  readonly bodyId: string;
  readonly presentation: Readonly<{
    kind: "png";
    resources: PngBodyResources;
  }>;
}

interface Live2DBodyPackage {
  readonly bodyId: string;
  readonly presentation: Readonly<{
    kind: "live2d";
    modelSource: TrustedLocalLive2DModelSource | TrustedManagedLive2DModelSource;
    coreReady: Live2DCoreReadyBoundary;
    fallbackResources: PngBodyResources;
  }>;
}

type BodyPackageDefinition = PngBodyPackage | Live2DBodyPackage;

type BodyPackageCatalog = Readonly<Record<string, BodyPackageDefinition>>;

interface ResolvedBodyPackage {
  readonly requestedBodyId: string;
  readonly effectiveBodyId: string;
  readonly usedFallback: boolean;
  readonly bodyPackage: BodyPackageDefinition;
}

interface PackageCompositionOptions {
  /** Internal test seam; production composition always uses the real adapter. */
  readonly live2dEngineFactory?: Live2DEngineFactory;
}

const DEFAULT_BODY_PACKAGE: PngBodyPackage = Object.freeze({
  bodyId: DEFAULT_BODY_ID,
  presentation: Object.freeze({
    kind: "png" as const,
    resources: DEFAULT_BUNDLED_PNG_RESOURCES,
  }),
});

// This catalog is intentionally module-private. Definitions and the shared
// resource descriptor are immutable configuration; each factory call still
// creates fresh provider and renderer runtime state. Managed snapshots replace
// this reference atomically after their complete validation pass.
let BODY_PACKAGE_CATALOG: BodyPackageCatalog = createDefaultBodyPackageCatalog();

function createDefaultBodyPackageCatalog(): BodyPackageCatalog {
  return Object.freeze({
    [DEFAULT_BODY_ID]: DEFAULT_BODY_PACKAGE,
  });
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  try {
    if (typeof value !== "object" || value === null || Array.isArray(value)) {
      return false;
    }
    const prototype = Object.getPrototypeOf(value);
    return prototype === Object.prototype || prototype === null;
  } catch {
    return false;
  }
}

function isValidAssetSnapshot(value: unknown): boolean {
  if (!isPlainRecord(value)) {
    return false;
  }
  const keys = Object.keys(value);
  if (
    keys.length !== 4 ||
    !["relativePath", "assetKind", "contentHash", "sizeBytes"].every((key) =>
      keys.includes(key),
    )
  ) {
    return false;
  }
  return (
    typeof value.relativePath === "string" &&
    value.relativePath.length > 0 &&
    !value.relativePath.includes("\\") &&
    !value.relativePath.split("/").some((part) => part === "" || part === "." || part === "..") &&
    typeof value.assetKind === "string" &&
    value.assetKind.length > 0 &&
    typeof value.contentHash === "string" &&
    value.contentHash.length > 0 &&
    typeof value.sizeBytes === "number" &&
    Number.isSafeInteger(value.sizeBytes) &&
    value.sizeBytes >= 0
  );
}

function isValidManagedSnapshot(value: unknown): value is InstalledBodyPackageSnapshot {
  if (!isPlainRecord(value)) {
    return false;
  }
  const keys = Object.keys(value);
  if (
    keys.length !== 9 ||
    ![
      "bodyId",
      "displayName",
      "presentationKind",
      "modelEntry",
      "packageContentHash",
      "packageVersion",
      "installedAt",
      "status",
      "assets",
    ].every((key) => keys.includes(key))
  ) {
    return false;
  }
  return (
    typeof value.bodyId === "string" &&
    value.bodyId.length > 0 &&
    typeof value.displayName === "string" &&
    value.displayName.length > 0 &&
    value.displayName.length <= 128 &&
    value.presentationKind === "live2d" &&
    typeof value.modelEntry === "string" &&
    typeof value.packageContentHash === "string" &&
    value.packageContentHash.length > 0 &&
    typeof value.packageVersion === "number" &&
    Number.isSafeInteger(value.packageVersion) &&
    value.packageVersion === 1 &&
    typeof value.installedAt === "string" &&
    value.installedAt.length > 0 &&
    (value.status === "available" || value.status === "corrupt-unavailable") &&
    Array.isArray(value.assets) &&
    value.assets.length <= 256 &&
    value.assets.every((asset) => isValidAssetSnapshot(asset))
  );
}

function buildManagedBodyPackage(
  snapshot: InstalledBodyPackageSnapshot,
): Live2DBodyPackage | undefined {
  if (snapshot.status !== "available") {
    return undefined;
  }
  const modelSource = createTrustedManagedLive2DModelSource({
    bodyId: snapshot.bodyId,
    modelEntry: snapshot.modelEntry,
  });
  return Object.freeze({
    bodyId: snapshot.bodyId,
    presentation: Object.freeze({
      kind: "live2d" as const,
      modelSource,
      coreReady: createLive2DCoreReadyBoundary(),
      fallbackResources: DEFAULT_BUNDLED_PNG_RESOURCES,
    }),
  });
}

/**
 * Atomically install the backend registry snapshot into the one production
 * body-package authority. Corrupt packages stay out of the renderer catalog;
 * Settings receives the original DTO separately so it can show them.
 */
export function installManagedBodyPackageRegistrySnapshot(
  snapshots: readonly InstalledBodyPackageSnapshot[],
): void {
  try {
    if (!Array.isArray(snapshots)) {
      throw new BodyRendererError("managed body package registry snapshot is invalid.");
    }

    const nextCatalog = Object.create(null) as Record<string, BodyPackageDefinition>;
    nextCatalog[DEFAULT_BODY_ID] = DEFAULT_BODY_PACKAGE;
    const seenBodyIds = new Set<string>([DEFAULT_BODY_ID]);

    for (const snapshot of snapshots) {
      if (!isValidManagedSnapshot(snapshot)) {
        throw new BodyRendererError("managed body package registry snapshot is invalid.");
      }
      if (seenBodyIds.has(snapshot.bodyId)) {
        throw new BodyRendererError("managed body package registry contains a duplicate bodyId.");
      }
      seenBodyIds.add(snapshot.bodyId);

      const packageDefinition = buildManagedBodyPackage(snapshot);
      if (packageDefinition !== undefined) {
        nextCatalog[snapshot.bodyId] = packageDefinition;
      }
    }

    BODY_PACKAGE_CATALOG = Object.freeze(nextCatalog);
  } catch (error) {
    if (error instanceof BodyRendererError) {
      throw error;
    }
    throw new BodyRendererError("managed body package registry snapshot is invalid.");
  }
}

/** Internal reset seam for isolated registry tests; not part of the body barrel. */
export function resetManagedLive2DModelPackageRegistryForTest(): void {
  BODY_PACKAGE_CATALOG = createDefaultBodyPackageCatalog();
}

function resolveBodyPackageFromCatalog(
  requestedBodyId: string,
  catalog: BodyPackageCatalog,
): ResolvedBodyPackage {
  const registered = Object.prototype.hasOwnProperty.call(
    catalog,
    requestedBodyId,
  )
    ? catalog[requestedBodyId]
    : undefined;

  if (registered !== undefined && registered.bodyId === requestedBodyId) {
    return {
      requestedBodyId,
      effectiveBodyId: registered.bodyId,
      usedFallback: false,
      bodyPackage: registered,
    };
  }

  return {
    requestedBodyId,
    effectiveBodyId: DEFAULT_BODY_ID,
    usedFallback: true,
    bodyPackage: DEFAULT_BODY_PACKAGE,
  };
}

/**
 * The only production bodyId/package resolution authority.  Binding metadata
 * is projected from this result; it is not maintained in a second catalog.
 */
export function resolveBodyPackage(
  requestedBodyId: string,
): ResolvedBodyPackage {
  return resolveBodyPackageFromCatalog(requestedBodyId, BODY_PACKAGE_CATALOG);
}

function composeBodyPackage(
  bodyPackage: BodyPackageDefinition,
  options: PackageCompositionOptions = {},
): BodyPresentationComposition {
  if (bodyPackage.presentation.kind === "png") {
    const resources = bodyPackage.presentation.resources;
    return {
      provider: new FallbackBodyProvider(
        new PngBodyProvider(resources),
        new PngBodyProvider(resources),
      ),
      renderer: new FallbackBodyRenderer(
        new PngBodyRenderer(),
        new PngBodyRenderer(),
      ),
    };
  }

  if (bodyPackage.presentation.kind === "live2d") {
    const { coreReady, fallbackResources, modelSource } =
      bodyPackage.presentation;
    // This is deliberately the final runtime check. A forged package object
    // cannot make a remote string reach Core readiness, Pixi allocation, or
    // model loading merely by matching the TypeScript shape.
    const modelUrl = requireTrustedLive2DModelUrl(modelSource);
    const live2dRenderer = new Live2DRenderer({
      modelUrl,
      coreReady,
    }, options.live2dEngineFactory);
    return {
      provider: new PngBodyProvider(fallbackResources),
      renderer: new FallbackBodyRenderer(
        live2dRenderer,
        new PngBodyRenderer(),
      ),
    };
  }

  throw new BodyRendererError("body package has no supported presentation.");
}

/**
 * Internal/test package-definition seam.  It is deliberately not exported
 * from the body barrel: production selection remains the opaque bodyId
 * resolver below, while focused tests can exercise a future package without
 * registering an asset or making it a production default.
 */
export function createPackagePresentationForDefinition(
  bodyPackage: BodyPackageDefinition,
  options: PackageCompositionOptions = {},
): BodyPresentationComposition {
  return composeBodyPackage(bodyPackage, options);
}

/**
 * Internal/test catalog seam.  It runs the same exact-match resolver and
 * composition path as production without registering a fabricated package in
 * the production catalog.  The catalog and options are intentionally absent
 * from the public body barrel.
 */
export function createPackagePresentationForTestCatalog(
  requestedBodyId: string,
  catalog: BodyPackageCatalog,
  options: PackageCompositionOptions = {},
): BodyPresentationComposition {
  return composeBodyPackage(
    resolveBodyPackageFromCatalog(requestedBodyId, catalog).bodyPackage,
    options,
  );
}

/** Internal/test projection of the same catalog authority. */
export function resolveBodyPackageForTestCatalog(
  requestedBodyId: string,
  catalog: BodyPackageCatalog,
): ResolvedBodyPackage {
  return resolveBodyPackageFromCatalog(requestedBodyId, catalog);
}

/** Canonical production composition selected by an opaque bodyId. */
export function createPackagePresentationForBodyId(
  requestedBodyId: string,
): BodyPresentationComposition {
  return composeBodyPackage(resolveBodyPackage(requestedBodyId).bodyPackage);
}
