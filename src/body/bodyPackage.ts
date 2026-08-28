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
import type { Live2DCoreReadyBoundary } from "./live2dRuntime.ts";
import type { TrustedLocalLive2DModelSource } from "./live2dModelSource.ts";
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
const BODY_PACKAGE_CATALOG: Readonly<Record<string, BodyPackageDefinition>> =
  Object.freeze({
    [DEFAULT_BODY_ID]: DEFAULT_BODY_PACKAGE,
  });

function getBodyPackage(bodyId: string): BodyPackageDefinition {
  const bodyPackage = BODY_PACKAGE_CATALOG[bodyId];
  if (bodyPackage === undefined || bodyPackage.bodyId !== bodyId) {
    throw new BodyRendererError("body package is unavailable.");
  }
  return bodyPackage;
}

function composeBodyPackage(
  bodyPackage: BodyPackageDefinition,
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
    const live2dRenderer = new Live2DRenderer({
      modelUrl: modelSource.path,
      coreReady,
    });
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
): BodyPresentationComposition {
  return composeBodyPackage(bodyPackage);
}

/**
 * Internal package-to-runtime composition boundary.  Callers reach this only
 * through bodyBinding's canonical bodyId resolver, never with raw resources.
 */
export function createPackagePresentation(
  effectiveBodyId: string,
): BodyPresentationComposition {
  return composeBodyPackage(getBodyPackage(effectiveBodyId));
}
