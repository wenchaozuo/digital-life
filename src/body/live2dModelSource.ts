import { BodyRendererError } from "./bodyRenderer.ts";

const LIVE2D_MODEL_FILE_SUFFIX = ".model3.json";
const TRUSTED_LOCAL_MODEL_SOURCE_ERROR =
  "Live2D model source must be a trusted local model path.";

/**
 * Presentation-local model-source value.  A package may carry this immutable
 * value, but bodyId, BodySnapshot, and user input never construct a source.
 */
export interface TrustedLocalLive2DModelSource {
  readonly kind: "trusted-local-live2d-model";
  readonly path: string;
}

/**
 * Accept only a packaged, local Cubism model descriptor.  The renderer still
 * receives a string because the third-party adapter requires one; the value
 * object is the boundary that prevents package configuration from silently
 * becoming a network, file-system, or arbitrary-scheme authority.
 */
export function isTrustedLocalLive2DModelPath(path: string): boolean {
  if (path.length === 0 || path.trim() !== path) {
    return false;
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(path)) {
    return false;
  }
  if (path.startsWith("//") || path.startsWith("\\\\")) {
    return false;
  }
  if (path.includes("\\") || path.includes("..")) {
    return false;
  }
  if (!path.startsWith("/") && !path.startsWith("./")) {
    return false;
  }
  return path.toLowerCase().endsWith(LIVE2D_MODEL_FILE_SUFFIX);
}

export function createTrustedLocalLive2DModelSource(
  path: string,
): TrustedLocalLive2DModelSource {
  if (!isTrustedLocalLive2DModelPath(path)) {
    throw new BodyRendererError(TRUSTED_LOCAL_MODEL_SOURCE_ERROR);
  }
  return Object.freeze({
    kind: "trusted-local-live2d-model" as const,
    path,
  });
}
