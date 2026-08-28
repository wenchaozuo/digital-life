import { BodyRendererError } from "./bodyRenderer.ts";
import { FallbackBodyRenderer } from "./fallbackBodyRenderer.ts";
import { FallbackBodyProvider } from "./fallbackBodyProvider.ts";
import { PngBodyRenderer } from "./pngBodyRenderer.ts";
import { PngBodyProvider } from "./pngBodyProvider.ts";
import {
  DEFAULT_BUNDLED_PNG_RESOURCES,
  type PngBodyResources,
} from "./pngBodyResources.ts";
import type { BodyPresentationComposition } from "./bodyBinding.ts";

export const DEFAULT_BODY_ID = "default-png";

interface BodyPackageDefinition {
  readonly bodyId: string;
  readonly presentation: Readonly<{
    kind: "png";
    resources: PngBodyResources;
  }>;
}

const DEFAULT_BODY_PACKAGE: BodyPackageDefinition = Object.freeze({
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

/**
 * Internal package-to-runtime composition boundary.  Callers reach this only
 * through bodyBinding's canonical bodyId resolver, never with raw resources.
 */
export function createPackagePresentation(
  effectiveBodyId: string,
): BodyPresentationComposition {
  const bodyPackage = getBodyPackage(effectiveBodyId);
  if (bodyPackage.presentation.kind !== "png") {
    throw new BodyRendererError("body package has no supported presentation.");
  }

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
