import { BodyRendererError } from "./bodyRenderer.ts";
import type { BodyRenderer } from "./bodyRenderer.ts";
import {
  createPackagePresentation,
  DEFAULT_BODY_ID,
} from "./bodyPackage.ts";
import type { BodyProvider } from "./types.ts";

export { DEFAULT_BODY_ID } from "./bodyPackage.ts";

export type BodyPresentationKind = "png" | "live2d";

interface BodyBindingDefinition {
  bodyId: string;
  presentationKind: BodyPresentationKind;
}

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

/** V1 contains exactly one application-owned production body binding. */
const BODY_BINDING_CATALOG: ReadonlyMap<string, BodyBindingDefinition> =
  new Map([[DEFAULT_BODY_ID, { bodyId: DEFAULT_BODY_ID, presentationKind: "png" }]]);

/**
 * Resolve an authoritative opaque body selector into a local presentation
 * projection.  The input is compared exactly and is never interpreted as a
 * path, URL, import specifier, or external resource location.
 */
export function resolveBodyBinding(requestedBodyId: string): ResolvedBodyBinding {
  const registered = BODY_BINDING_CATALOG.get(requestedBodyId);
  if (registered !== undefined) {
    return {
      requestedBodyId,
      effectiveBodyId: registered.bodyId,
      usedFallback: false,
      presentationKind: registered.presentationKind,
    };
  }

  return {
    requestedBodyId,
    effectiveBodyId: DEFAULT_BODY_ID,
    usedFallback: true,
    presentationKind: "png",
  };
}

/**
 * Create a matched provider/renderer pair for one resolved binding.  Both
 * halves are fresh, so mutable provider and renderer state cannot cross Life
 * presentation compositions.
 */
function createBodyPresentationForBinding(
  binding: ResolvedBodyBinding,
): BodyPresentationComposition {
  if (
    binding.effectiveBodyId !== DEFAULT_BODY_ID ||
    binding.presentationKind !== "png"
  ) {
    throw new BodyRendererError("body binding has no supported presentation.");
  }

  return createPackagePresentation(binding.effectiveBodyId);
}

/** Resolve a selector and create its matched presentation composition. */
export function createBodyPresentationForBodyId(
  requestedBodyId: string,
): BodyPresentationComposition {
  return createBodyPresentationForBinding(resolveBodyBinding(requestedBodyId));
}
