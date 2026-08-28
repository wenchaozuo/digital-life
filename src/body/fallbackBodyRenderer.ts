import { BodyRendererError } from "./bodyRenderer.ts";
import type { BodyRenderer } from "./bodyRenderer.ts";
import type { BodySnapshot } from "./types.ts";

type FallbackRendererMode =
  | "unmounted"
  | "mounting"
  | "primary"
  | "fallback"
  | "disposed";

const MOUNT_FAILURE_MESSAGE = "body renderer mount failed.";
const FALLBACK_ACTIVATION_FAILURE_MESSAGE =
  "body renderer fallback activation failed.";
const FALLBACK_RENDER_FAILURE_MESSAGE = "body renderer fallback render failed.";

/**
 * Renderer-level presentation firewall.  It permanently retires a primary
 * renderer after a mount/render failure and keeps the supplied host on the
 * fallback renderer for the rest of that mounted lifetime.
 *
 * BodyRendererHost owns lifecycle serialization.  This wrapper therefore
 * does not introduce a second render queue; it only selects the active
 * renderer and contains renderer failures at the presentation boundary.
 */
export class FallbackBodyRenderer implements BodyRenderer {
  private readonly primary: BodyRenderer;
  private readonly fallback: BodyRenderer;
  private mode: FallbackRendererMode = "unmounted";
  private host: HTMLElement | undefined;
  private pendingMount: Promise<void> | undefined;
  private disposePromise: Promise<void> | undefined;
  private primaryCleanupOwned = false;
  private fallbackCleanupOwned = false;
  private fallbackMounted = false;
  private disposedRenderers = new WeakSet<BodyRenderer>();

  constructor(primary: BodyRenderer, fallback: BodyRenderer) {
    this.primary = primary;
    this.fallback = fallback;
  }

  mount(host: HTMLElement): Promise<void> {
    if (this.mode === "disposed") {
      return Promise.reject(new BodyRendererError("body renderer is disposed."));
    }
    if (this.mode === "primary" || this.mode === "fallback") {
      if (this.host === host) {
        return Promise.resolve();
      }
      return Promise.reject(
        new BodyRendererError(
          "body renderer is already mounted to a different element.",
        ),
      );
    }
    if (this.mode === "mounting") {
      if (this.host === host && this.pendingMount !== undefined) {
        return this.pendingMount;
      }
      return Promise.reject(
        new BodyRendererError("body renderer is already mounting."),
      );
    }

    const previousHost = this.host;
    this.mode = "mounting";
    this.host = host;
    const mountPromise = this.mountFresh(host, previousHost).catch(
      (error: unknown) => {
        if (this.mode !== "disposed") {
          this.mode = "unmounted";
          this.host = undefined;
        }
        if (error instanceof BodyRendererError) {
          throw error;
        }
        throw new BodyRendererError(MOUNT_FAILURE_MESSAGE);
      },
    );
    this.pendingMount = mountPromise;
    return mountPromise;
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    if (this.mode === "disposed") {
      throw new BodyRendererError("body renderer is disposed.");
    }
    if (this.mode === "unmounted") {
      throw new BodyRendererError("body renderer is not mounted.");
    }
    if (this.mode === "mounting") {
      const pendingMount = this.pendingMount;
      if (pendingMount === undefined) {
        throw new BodyRendererError("body renderer is not mounted.");
      }
      try {
        await pendingMount;
      } catch {
        throw new BodyRendererError("body renderer is not mounted.");
      }
      const modeAfterMount = this.currentMode();
      if (modeAfterMount !== "primary" && modeAfterMount !== "fallback") {
        throw new BodyRendererError("body renderer is not mounted.");
      }
    }

    if (this.mode === "primary") {
      if (await this.tryRender(this.primary, snapshot)) {
        return;
      }
      await this.failoverToFallback(snapshot);
      return;
    }

    await this.renderWithFallback(snapshot);
  }

  async dispose(): Promise<void> {
    if (this.mode === "disposed") {
      await this.disposePromise;
      return;
    }

    const pendingMount = this.pendingMount;
    const host = this.host;
    this.mode = "disposed";
    this.host = undefined;
    this.fallbackMounted = false;
    this.disposePromise = (async () => {
      if (pendingMount !== undefined) {
        try {
          await pendingMount;
        } catch {
          // Mount failure is already contained by the mount promise.
        }
      }
      await this.disposePrimaryOnce();
      await this.disposeFallbackOnce();
      this.clearHostElement(host);
    })();
    await this.disposePromise;
  }

  private async mountFresh(
    host: HTMLElement,
    previousHost: HTMLElement | undefined,
  ): Promise<void> {
    await this.prepareFreshLifetime(previousHost);
    if (this.currentMode() === "disposed") {
      this.clearHostElement(host);
      return;
    }

    // Ownership starts before invocation because a renderer may partially
    // mutate the host and then throw or reject from mount.
    this.primaryCleanupOwned = true;
    const primaryMounted = await this.tryMount(this.primary, host);
    if (this.currentMode() === "disposed") {
      await this.disposePrimaryOnce();
      this.clearHostElement(host);
      return;
    }
    if (primaryMounted) {
      this.mode = "primary";
      return;
    }

    await this.disposePrimaryOnce();
    this.clearHostElement(host);
    this.mode = "fallback";
    const fallbackMounted = await this.mountFallback(host);
    if (this.currentMode() === "disposed") {
      await this.disposeFallbackOnce();
      this.clearHostElement(host);
      return;
    }
    if (!fallbackMounted) {
      this.clearHostElement(host);
      this.mode = "unmounted";
      this.host = undefined;
      throw new BodyRendererError(MOUNT_FAILURE_MESSAGE);
    }
  }

  private async prepareFreshLifetime(
    previousHost: HTMLElement | undefined,
  ): Promise<void> {
    await this.disposePrimaryOnce();
    await this.disposeFallbackOnce();
    this.clearHostElement(previousHost);
    if (this.currentMode() === "disposed") {
      return;
    }
    this.primaryCleanupOwned = false;
    this.fallbackCleanupOwned = false;
    this.fallbackMounted = false;
    this.disposedRenderers = new WeakSet<BodyRenderer>();
  }

  private async failoverToFallback(snapshot: BodySnapshot): Promise<void> {
    await this.disposePrimaryOnce();
    if (this.currentMode() === "disposed") {
      throw new BodyRendererError("body renderer is disposed.");
    }
    const host = this.host;
    if (host === undefined) {
      throw new BodyRendererError(FALLBACK_ACTIVATION_FAILURE_MESSAGE);
    }
    this.clearHostElement(host);
    this.mode = "fallback";
    if (!(await this.mountFallback(host))) {
      this.clearHostElement(host);
      throw new BodyRendererError(FALLBACK_ACTIVATION_FAILURE_MESSAGE);
    }
    if (this.currentMode() === "disposed") {
      throw new BodyRendererError("body renderer is disposed.");
    }
    if (!(await this.tryRender(this.fallback, snapshot))) {
      throw new BodyRendererError(FALLBACK_RENDER_FAILURE_MESSAGE);
    }
  }

  private async renderWithFallback(snapshot: BodySnapshot): Promise<void> {
    const host = this.host;
    if (host === undefined) {
      throw new BodyRendererError(FALLBACK_ACTIVATION_FAILURE_MESSAGE);
    }
    if (!this.fallbackMounted && !(await this.mountFallback(host))) {
      this.clearHostElement(host);
      throw new BodyRendererError(FALLBACK_ACTIVATION_FAILURE_MESSAGE);
    }
    if (this.currentMode() === "disposed") {
      throw new BodyRendererError("body renderer is disposed.");
    }
    if (!(await this.tryRender(this.fallback, snapshot))) {
      throw new BodyRendererError(FALLBACK_RENDER_FAILURE_MESSAGE);
    }
  }

  private async mountFallback(host: HTMLElement): Promise<boolean> {
    // Ownership starts before invocation so a failed fallback mount remains
    // disposable and can be retried without re-entering the primary mode.
    this.fallbackCleanupOwned = true;
    const mounted = await this.tryMount(this.fallback, host);
    this.fallbackMounted = mounted;
    return mounted;
  }

  private currentMode(): FallbackRendererMode {
    return this.mode;
  }

  private async tryMount(renderer: BodyRenderer, host: HTMLElement): Promise<boolean> {
    try {
      await renderer.mount(host);
      return true;
    } catch {
      return false;
    }
  }

  private async tryRender(
    renderer: BodyRenderer,
    snapshot: BodySnapshot,
  ): Promise<boolean> {
    try {
      await renderer.render(snapshot);
      return true;
    } catch {
      return false;
    }
  }

  private async disposePrimaryOnce(): Promise<void> {
    if (!this.primaryCleanupOwned) {
      return;
    }
    this.primaryCleanupOwned = false;
    await this.disposeRendererContained(this.primary);
  }

  private async disposeFallbackOnce(): Promise<void> {
    if (!this.fallbackCleanupOwned) {
      return;
    }
    this.fallbackCleanupOwned = false;
    await this.disposeRendererContained(this.fallback);
  }

  private async disposeRendererContained(renderer: BodyRenderer): Promise<void> {
    if (this.disposedRenderers.has(renderer)) {
      return;
    }
    this.disposedRenderers.add(renderer);
    try {
      await renderer.dispose();
    } catch {
      // Renderer cleanup is best-effort and never escapes the presentation
      // boundary or becomes an unhandled rejection.
    }
  }

  private clearHostElement(host: HTMLElement | undefined): void {
    if (host === undefined) {
      return;
    }
    try {
      host.replaceChildren();
    } catch {
      // Host cleanup remains best-effort and renderer-local.
    }
  }
}
