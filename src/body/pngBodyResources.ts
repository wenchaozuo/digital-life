import { BodyRendererError } from "./bodyRenderer.ts";
import { BODY_STATES, type BodyState } from "./types.ts";
import idleBodyResource from "../assets/body/digital-life-idle.png";

/** The bounded resource descriptor accepted by a PNG body provider. */
export type PngBodyResources = Readonly<Record<BodyState, string>>;

/**
 * The one bundled V1 PNG asset is truthful for every frozen body state.  The
 * package layer chooses this descriptor for `default-png`; the provider only
 * consumes a supplied descriptor.
 */
export const DEFAULT_BUNDLED_PNG_RESOURCES: PngBodyResources = Object.freeze({
  idle: idleBodyResource,
  thinking: idleBodyResource,
  speaking: idleBodyResource,
  waiting: idleBodyResource,
  error: idleBodyResource,
});

const INVALID_PNG_BODY_RESOURCES_MESSAGE = "invalid PNG body resources.";

function invalidPngBodyResources(): never {
  throw new BodyRendererError(INVALID_PNG_BODY_RESOURCES_MESSAGE);
}

function readResource(
  resources: Record<string, unknown>,
  state: BodyState,
): string {
  const resource = resources[state];
  if (typeof resource !== "string" || resource.trim().length === 0) {
    return invalidPngBodyResources();
  }
  return resource;
}

/**
 * Validate the exact five-state shape and retain a private frozen copy.  Any
 * malformed caller object is reduced to one bounded presentation error; no
 * resource value or arbitrary configuration detail escapes the boundary.
 */
export function copyValidatedPngBodyResources(
  resources: PngBodyResources,
): PngBodyResources {
  try {
    if (
      typeof resources !== "object" ||
      resources === null ||
      Array.isArray(resources)
    ) {
      return invalidPngBodyResources();
    }

    const candidate = resources as unknown as Record<string, unknown>;
    const keys = Object.keys(candidate);
    if (
      keys.length !== BODY_STATES.length ||
      !BODY_STATES.every((state) => keys.includes(state))
    ) {
      return invalidPngBodyResources();
    }

    return Object.freeze({
      idle: readResource(candidate, "idle"),
      thinking: readResource(candidate, "thinking"),
      speaking: readResource(candidate, "speaking"),
      waiting: readResource(candidate, "waiting"),
      error: readResource(candidate, "error"),
    });
  } catch (error: unknown) {
    if (error instanceof BodyRendererError) {
      throw error;
    }
    return invalidPngBodyResources();
  }
}
