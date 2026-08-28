import type { BodyRenderer } from "./bodyRenderer.ts";
import {
  createPackagePresentationForBodyId,
  createPackagePresentationForTestCatalog,
  resolveBodyPackage,
  resolveBodyPackageForTestCatalog,
} from "./bodyPackage.ts";
import type { BodyProvider } from "./types.ts";

export { DEFAULT_BODY_ID } from "./bodyPackage.ts";

export type BodyPresentationKind = "png" | "live2d";

export interface ResolvedBodyBinding {
  requestedBodyId: string;
  effectiveBodyId: string;
  usedFallback: boolean;
  presentationKind: BodyPresentationKind;
}

export interface BodyPresentationComposition {
  provider: BodyProvider;
  renderer: BodyRenderer;
}

type TestPackageCatalog = Parameters<
  typeof createPackagePresentationForTestCatalog
>[1];
type TestPackageCompositionOptions = Parameters<
  typeof createPackagePresentationForTestCatalog
>[2];

function projectBodyBinding(
  requestedBodyId: string,
  resolved: ReturnType<typeof resolveBodyPackage>,
): ResolvedBodyBinding {
  return {
    requestedBodyId,
    effectiveBodyId: resolved.effectiveBodyId,
    usedFallback: resolved.usedFallback,
    presentationKind: resolved.bodyPackage.presentation.kind,
  };
}

/**
 * Project the single body-package authority into the binding shape consumed
 * by callers.  The input is compared exactly and is never interpreted as a
 * path, URL, import specifier, or external resource location.
 */
export function resolveBodyBinding(requestedBodyId: string): ResolvedBodyBinding {
  return projectBodyBinding(
    requestedBodyId,
    resolveBodyPackage(requestedBodyId),
  );
}

/** Resolve a selector and create its matched presentation composition. */
export function createBodyPresentationForBodyId(
  requestedBodyId: string,
): BodyPresentationComposition {
  // The package module performs the same exact lookup used by
  // resolveBodyBinding, then composes from that resolved definition.  There
  // is no second binding catalog or effective-id-to-presentation assumption.
  return createPackagePresentationForBodyId(requestedBodyId);
}

/**
 * Internal/test-only version of the canonical bodyId factory.  It exists so
 * a controlled future package can exercise the exact same binding projection
 * and package composition without becoming a production catalog entry.
 */
export function createBodyPresentationForTestCatalog(
  requestedBodyId: string,
  catalog: TestPackageCatalog,
  options?: TestPackageCompositionOptions,
): BodyPresentationComposition {
  return createPackagePresentationForTestCatalog(requestedBodyId, catalog, options);
}

/** Internal/test-only binding projection over the same package authority. */
export function resolveBodyBindingForTestCatalog(
  requestedBodyId: string,
  catalog: Parameters<typeof resolveBodyPackageForTestCatalog>[1],
): ResolvedBodyBinding {
  return projectBodyBinding(
    requestedBodyId,
    resolveBodyPackageForTestCatalog(requestedBodyId, catalog),
  );
}
