import { BodyRendererError } from "./bodyRenderer.ts";

const LIVE2D_MODEL_FILE_SUFFIX = ".model3.json";
const TRUSTED_LOCAL_MODEL_SOURCE_ERROR =
  "Live2D model source must be a trusted local model path.";
const TRUSTED_MANAGED_MODEL_SOURCE_ERROR =
  "Live2D model source must be a trusted managed body asset URL.";
const TRUSTED_MODEL_SOURCE_ERROR =
  "Live2D model source is not a trusted local or managed source.";
const trustedLocalLive2DModelSourceBrand: unique symbol = Symbol(
  "trusted-local-live2d-model-source",
);
const trustedManagedLive2DModelSourceBrand: unique symbol = Symbol(
  "trusted-managed-live2d-model-source",
);

const WINDOWS_ANDROID_BODY_ASSET_ORIGIN =
  "http://digital-life-body.localhost/";
const MAC_LINUX_BODY_ASSET_ORIGIN = "digital-life-body://localhost/";
const MANAGED_BODY_ID_PATTERN = /^live2d-[0-9a-f]+$/;

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
 * Immutable source value created only from a backend registry snapshot.
 * `bodyId` is retained beside the URL so runtime validation can verify that
 * the URL still names the registered package that supplied it.
 */
interface TrustedManagedLive2DModelSnapshot {
  readonly bodyId: string;
  readonly modelEntry: string;
}

export interface TrustedManagedLive2DModelSource {
  readonly [trustedManagedLive2DModelSourceBrand]: true;
  readonly kind: "trusted-managed-live2d-model";
  readonly bodyId: string;
  readonly url: string;
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

function isManagedBodyId(value: string): boolean {
  return value.length <= 96 && MANAGED_BODY_ID_PATTERN.test(value);
}

function hasUnsafeEncodedPathComponent(path: string): boolean {
  return /%(?:2e|2f|5c)/i.test(path);
}

function hasUnsafeDecodedPath(path: string): boolean {
  if (path.includes("\\") || path.includes("//")) {
    return true;
  }
  return path.split("/").some((component) => component === "." || component === "..");
}

function isTrustedManagedLive2DModelEntry(
  bodyId: string,
  modelEntry: string,
): boolean {
  if (
    !isManagedBodyId(bodyId) ||
    modelEntry.length === 0 ||
    modelEntry.trim() !== modelEntry ||
    modelEntry.includes("\\") ||
    hasUnsafeEncodedPathComponent(modelEntry)
  ) {
    return false;
  }

  const origin = [
    WINDOWS_ANDROID_BODY_ASSET_ORIGIN,
    MAC_LINUX_BODY_ASSET_ORIGIN,
  ].find((candidate) => modelEntry.startsWith(candidate));
  if (origin === undefined) {
    return false;
  }

  const pathPart = modelEntry.slice(origin.length);
  const rawSegments = pathPart.split("/");
  if (
    rawSegments.length < 2 ||
    rawSegments[0] !== bodyId ||
    rawSegments.some((segment) => segment.length === 0 || segment === "." || segment === "..")
  ) {
    return false;
  }
  if (/%(?![0-9a-f]{2})/i.test(pathPart)) {
    return false;
  }

  let parsed: URL;
  try {
    parsed = new URL(modelEntry);
  } catch {
    return false;
  }
  if (
    parsed.username.length > 0 ||
    parsed.password.length > 0 ||
    parsed.port.length > 0 ||
    parsed.search.length > 0 ||
    parsed.hash.length > 0
  ) {
    return false;
  }
  if (
    parsed.protocol === "http:" &&
    parsed.hostname !== "digital-life-body.localhost"
  ) {
    return false;
  }
  if (
    parsed.protocol === "digital-life-body:" &&
    parsed.hostname !== "localhost"
  ) {
    return false;
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "digital-life-body:") {
    return false;
  }

  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(parsed.pathname).slice(1);
  } catch {
    return false;
  }
  if (hasUnsafeDecodedPath(decodedPath)) {
    return false;
  }
  try {
    // A second decode catches encoded traversal without rejecting an ordinary
    // percent character in a legitimate managed filename.
    const twiceDecoded = decodeURIComponent(decodedPath);
    if (hasUnsafeDecodedPath(twiceDecoded)) {
      return false;
    }
  } catch {
    // A literal percent character after the first decode is allowed.
  }

  const decodedSegments = decodedPath.split("/");
  const finalSegment = decodedSegments[decodedSegments.length - 1];
  return (
    decodedSegments.length >= 2 &&
    decodedSegments[0] === bodyId &&
    decodedSegments.every((segment) => segment.length > 0) &&
    finalSegment !== undefined &&
    finalSegment.toLowerCase().endsWith(LIVE2D_MODEL_FILE_SUFFIX)
  );
}

export function isTrustedManagedLive2DModelSource(
  value: unknown,
): value is TrustedManagedLive2DModelSource {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  try {
    const candidate = value as {
      readonly [trustedManagedLive2DModelSourceBrand]?: unknown;
      readonly kind?: unknown;
      readonly bodyId?: unknown;
      readonly url?: unknown;
    };
    return (
      candidate[trustedManagedLive2DModelSourceBrand] === true &&
      candidate.kind === "trusted-managed-live2d-model" &&
      typeof candidate.bodyId === "string" &&
      typeof candidate.url === "string" &&
      isTrustedManagedLive2DModelEntry(candidate.bodyId, candidate.url)
    );
  } catch {
    return false;
  }
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
  try {
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
  } catch {
    return false;
  }
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

export function requireTrustedManagedLive2DModelUrl(value: unknown): string {
  if (!isTrustedManagedLive2DModelSource(value)) {
    throw new BodyRendererError(TRUSTED_MANAGED_MODEL_SOURCE_ERROR);
  }
  return value.url;
}

/**
 * The final renderer-facing extraction boundary.  It accepts unknown at the
 * package/runtime edge and revalidates both the private brand and canonical
 * source policy immediately before a Live2D adapter is constructed.
 */
export function requireTrustedLive2DModelUrl(value: unknown): string {
  if (isTrustedLocalLive2DModelSource(value)) {
    return requireTrustedLocalLive2DModelPath(value);
  }
  if (isTrustedManagedLive2DModelSource(value)) {
    return requireTrustedManagedLive2DModelUrl(value);
  }
  throw new BodyRendererError(TRUSTED_MODEL_SOURCE_ERROR);
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

/**
 * Construct a managed source only from the paired backend snapshot fields.
 * There is intentionally no public URL-only constructor and this factory is
 * not re-exported from the body barrel.
 */
export function createTrustedManagedLive2DModelSource(
  snapshot: TrustedManagedLive2DModelSnapshot,
): TrustedManagedLive2DModelSource {
  try {
    if (
      typeof snapshot !== "object" ||
      snapshot === null ||
      !isTrustedManagedLive2DModelEntry(snapshot.bodyId, snapshot.modelEntry)
    ) {
      throw new BodyRendererError(TRUSTED_MANAGED_MODEL_SOURCE_ERROR);
    }
  } catch (error) {
    if (error instanceof BodyRendererError) {
      throw error;
    }
    throw new BodyRendererError(TRUSTED_MANAGED_MODEL_SOURCE_ERROR);
  }
  return Object.freeze({
    [trustedManagedLive2DModelSourceBrand]: true as const,
    kind: "trusted-managed-live2d-model" as const,
    bodyId: snapshot.bodyId,
    url: snapshot.modelEntry,
  });
}
