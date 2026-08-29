import { invoke } from "@tauri-apps/api/core";

import {
  createLive2DCoreReadyBoundary,
  Live2DCoreUnavailableError,
  type Live2DCoreReadyBoundary,
} from "./live2dRuntime.ts";

// D22-D1 managed Cubism Core provisioning boundary (frontend half).
//
// The backend is the authority: it owns the allowlist, the managed storage,
// the SQLite component row, and the main-only `digital-life-core` protocol.
// This module only (a) validates the backend-certified script URL shape and
// (b) injects exactly that one trusted script once, then delegates to the
// frozen D21 `createLive2DCoreReadyBoundary()`.
//
// The managed boundary NEVER fetches a CDN, GitHub, or any arbitrary HTTP
// resource: the only accepted script location is the backend-generated
// managed Core URL.

export const MANAGED_CORE_SCRIPT_FILENAME = "live2dcubismcore.min.js";

export type ManagedCubismCoreStatus =
  | "not-configured"
  | "ready-for-startup"
  | "corrupt-unavailable"
  | "restart-required";

export interface ManagedCubismCoreSnapshot {
  status: ManagedCubismCoreStatus;
  runtimeFamily: "cubism4";
  versionLabel?: string;
  sha256?: string;
  scriptUrl?: string;
  restartRequired: boolean;
}

const WINDOWS_ANDROID_CORE_ORIGIN = "http://digital-life-core.localhost/";
const MAC_LINUX_CORE_ORIGIN = "digital-life-core://localhost/";

/**
 * Accepts ONLY the exact backend-generated managed Core URL shapes:
 *
 * - Windows/Android: `http://digital-life-core.localhost/live2dcubismcore.min.js`
 * - macOS/Linux:     `digital-life-core://localhost/live2dcubismcore.min.js`
 *
 * Everything else is rejected: generic http/https origins, file URLs, wrong
 * scheme, wrong host, port, auth, query, fragment, alternate pathname,
 * traversal, and encoded traversal.
 */
export function isTrustedManagedCoreScriptUrl(value: string): boolean {
  if (typeof value !== "string" || value.length === 0) {
    return false;
  }
  const windowsShape = `${WINDOWS_ANDROID_CORE_ORIGIN}${MANAGED_CORE_SCRIPT_FILENAME}`;
  const macLinuxShape = `${MAC_LINUX_CORE_ORIGIN}${MANAGED_CORE_SCRIPT_FILENAME}`;
  if (value === windowsShape || value === macLinuxShape) {
    return true;
  }
  return false;
}

/**
 * Narrow frontend boundary for the backend Cubism Core authority.  Only the
 * snapshot DTO and status are transported; no allowlist or hash can be
 * supplied dynamically.
 */
export class ManagedCubismCoreService {
  async getSnapshot(): Promise<ManagedCubismCoreSnapshot> {
    return invoke<ManagedCubismCoreSnapshot>("get_cubism_core_snapshot");
  }
}

export const managedCubismCoreService = new ManagedCubismCoreService();

interface WindowWithCubismCore extends Window {
  Live2DCubismCore?: unknown;
}

function hasCubismCore(): boolean {
  return (window as WindowWithCubismCore).Live2DCubismCore !== undefined;
}

/**
 * D22-D1 production managed Core ready boundary.
 *
 * `ensureReady()`:
 * 1. If `window.Live2DCubismCore` is already present, delegate directly to
 *    the frozen D21 boundary (no second script, no re-provision).
 * 2. Otherwise read the backend Core snapshot, require an approved managed
 *    descriptor with a trusted `scriptUrl`, inject exactly that script once,
 *    await its load, verify the Core global exists, then delegate to the D21
 *    boundary.
 *
 * Concurrency: concurrent `ensureReady()` calls share one in-flight
 * readiness promise, so exactly one script element and one initialization
 * path run.  A failed script load never marks Core ready and returns a
 * bounded Core startup error; the PNG fallback remains usable and a later
 * application restart may retry.
 */
export class ManagedCubismCoreReadyBoundary implements Live2DCoreReadyBoundary {
  private inFlight: Promise<void> | undefined;

  constructor(
    private readonly service: ManagedCubismCoreService = managedCubismCoreService,
    private readonly documentRef: Document = document,
    private readonly delegateFactory: () => Live2DCoreReadyBoundary = createLive2DCoreReadyBoundary,
  ) {}

  ensureReady(): Promise<void> {
    if (this.inFlight !== undefined) {
      return this.inFlight;
    }
    this.inFlight = this.runEnsureReady().finally(() => {
      this.inFlight = undefined;
    });
    return this.inFlight;
  }

  private async readAuthoritativeSnapshot(): Promise<ManagedCubismCoreSnapshot> {
    try {
      return await this.service.getSnapshot();
    } catch {
      // Backend unavailability is contained into the same bounded Core
      // unavailable error; the PNG fallback remains usable.
      throw new Live2DCoreUnavailableError();
    }
  }

  private async runEnsureReady(): Promise<void> {
    if (hasCubismCore()) {
      await this.delegateFactory().ensureReady();
      return;
    }

    const snapshot = await this.readAuthoritativeSnapshot();
    if (
      snapshot.status !== "ready-for-startup" ||
      snapshot.scriptUrl === undefined ||
      !isTrustedManagedCoreScriptUrl(snapshot.scriptUrl)
    ) {
      throw new Live2DCoreUnavailableError();
    }

    const script = this.documentRef.createElement("script");
    script.src = snapshot.scriptUrl;
    script.async = true;
    let settled = false;
    const loaded = new Promise<void>((resolve, reject) => {
      const onLoad = (): void => {
        if (settled) {
          return;
        }
        settled = true;
        resolve();
      };
      const onError = (): void => {
        if (settled) {
          return;
        }
        settled = true;
        reject(new Live2DCoreUnavailableError());
      };
      script.addEventListener("load", onLoad, { once: true });
      script.addEventListener("error", onError, { once: true });
    });
    this.documentRef.head.appendChild(script);
    try {
      await loaded;
    } catch (error) {
      // Retire the failed script element; Core is not ready.  Late error
      // events after settlement are ignored by the guard above.
      script.remove();
      throw error instanceof Live2DCoreUnavailableError
        ? error
        : new Live2DCoreUnavailableError();
    }
    if (!hasCubismCore()) {
      script.remove();
      throw new Live2DCoreUnavailableError();
    }
    await this.delegateFactory().ensureReady();
  }
}

export function createManagedCubismCoreReadyBoundary(): Live2DCoreReadyBoundary {
  return new ManagedCubismCoreReadyBoundary();
}