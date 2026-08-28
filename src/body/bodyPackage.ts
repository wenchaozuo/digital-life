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
  requireTrustedLocalLive2DModelPath,
  type TrustedLocalLive2DModelSource,
} from "./live2dModelSource.ts";
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
    modelSource: TrustedLocalLive2DModelSource;
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

// This catalog is intentionally module-private.  Definitions and the shared
// resource descriptor are immutable configuration; each factory call still
// creates fresh provider and renderer runtime state.
const BODY_PACKAGE_CATALOG: BodyPackageCatalog = Object.freeze({
  [DEFAULT_BODY_ID]: DEFAULT_BODY_PACKAGE,
});

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
    const modelUrl = requireTrustedLocalLive2DModelPath(modelSource);
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
