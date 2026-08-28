import { BodyRendererError } from "./bodyRenderer.ts";

const LIVE2D_MODEL_FILE_SUFFIX = ".model3.json";
const TRUSTED_LOCAL_MODEL_SOURCE_ERROR =
  "Live2D model source must be a trusted local model path.";
const trustedLocalLive2DModelSourceBrand: unique symbol = Symbol(
  "trusted-local-live2d-model-source",
);

/**
 * Presentation-local model-source value.  A package may carry this immutable
 * value, but bodyId, BodySnapshot, and user input never construct a source.
 */
export interface TrustedLocalLive2DModelSource {
  readonly [trustedLocalLive2DModelSourceBrand]: true;
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

/**
 * Runtime authority check for a package value.  The private brand blocks
 * ordinary structural construction, while the path validator is retained so
 * a forged or tampered runtime object cannot reach the renderer.
 */
export function isTrustedLocalLive2DModelSource(
  value: unknown,
): value is TrustedLocalLive2DModelSource {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as {
    readonly [trustedLocalLive2DModelSourceBrand]?: unknown;
    readonly kind?: unknown;
    readonly path?: unknown;
  };
  return (
    candidate[trustedLocalLive2DModelSourceBrand] === true &&
    candidate.kind === "trusted-local-live2d-model" &&
    typeof candidate.path === "string" &&
    isTrustedLocalLive2DModelPath(candidate.path)
  );
}

/**
 * Canonical bounded extraction used by package composition immediately before
 * a Live2D renderer is constructed.  It intentionally accepts unknown so the
 * runtime boundary does not trust TypeScript's structural view of a package.
 */
export function requireTrustedLocalLive2DModelPath(value: unknown): string {
  if (!isTrustedLocalLive2DModelSource(value)) {
    throw new BodyRendererError(TRUSTED_LOCAL_MODEL_SOURCE_ERROR);
  }
  return value.path;
}

export function createTrustedLocalLive2DModelSource(
  path: string,
): TrustedLocalLive2DModelSource {
  if (!isTrustedLocalLive2DModelPath(path)) {
    throw new BodyRendererError(TRUSTED_LOCAL_MODEL_SOURCE_ERROR);
  }
  return Object.freeze({
    [trustedLocalLive2DModelSourceBrand]: true as const,
    kind: "trusted-local-live2d-model" as const,
    path,
  });
}
