import { BodyRendererError } from "./bodyRenderer.ts";
import type { BodyRenderer } from "./bodyRenderer.ts";
import type { BodySnapshot } from "./types.ts";
import type {
  Live2DEngine,
  Live2DEngineFactory,
  Live2DRendererConfig,
} from "./live2dRuntime.ts";
import { createPixiCubism4Live2DEngine } from "./live2dRuntime.ts";

export type {
  Live2DCoreReadyBoundary,
  Live2DEngine,
  Live2DEngineFactory,
  Live2DRendererConfig,
} from "./live2dRuntime.ts";
export {
  LIVE2D_CORE_STARTUP_FAILURE_MESSAGE,
  LIVE2D_CORE_UNAVAILABLE_MESSAGE,
  Live2DCoreStartupError,
  Live2DCoreUnavailableError,
  calculateLive2DModelLayout,
  createLive2DCoreReadyBoundary,
  createPixiCubism4Live2DEngine,
  measureLive2DHost,
  normalizeLive2DHostSize,
} from "./live2dRuntime.ts";
export type {
  Live2DModelLayout,
  Live2DModelSize,
  Live2DViewportSize,
} from "./live2dRuntime.ts";

type Live2DRendererPhase =
  | "unmounted"
  | "mounting"
  | "mounted"
  | "disposed";

const MOUNT_FAILURE_MESSAGE = "Live2D renderer mount failed.";
const RENDER_FAILURE_MESSAGE = "Live2D renderer render failed.";
const RESIZE_FAILURE_MESSAGE = "Live2D renderer resize failed.";

/**
 * Creates the Core-dependent engine only after the renderer lifecycle has
 * entered mount. The runtime module itself is Core-free; it performs the
 * explicit Core-ready check before allocating Pixi or Live2D resources.
 */
class LazyPixiCubism4Engine implements Live2DEngine {
  private readonly config: Live2DRendererConfig;
  private delegate: Live2DEngine | undefined;
  private loading: Promise<Live2DEngine> | undefined;
  private disposed = false;

  constructor(config: Live2DRendererConfig) {
    this.config = config;
  }

  async mount(host: HTMLElement, modelUrl: string): Promise<void> {
    if (this.disposed) {
      throw new BodyRendererError(MOUNT_FAILURE_MESSAGE);
    }
    const delegate = await this.loadDelegate();
    if (this.disposed) {
      await delegate.dispose();
      return;
    }
    await delegate.mount(host, modelUrl);
  }

  resize(): void {
    const delegate = this.delegate;
    if (this.disposed || delegate === undefined) {
      throw new BodyRendererError(RESIZE_FAILURE_MESSAGE);
    }
    delegate.resize();
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    const delegate = this.delegate;
    if (this.disposed || delegate === undefined) {
      throw new BodyRendererError("Live2D renderer is not mounted.");
    }
    await delegate.render(snapshot);
  }

  async dispose(): Promise<void> {
    this.disposed = true;
    const loading = this.loading;
    if (loading !== undefined) {
      try {
        const delegate = await loading;
        await delegate.dispose();
      } catch {
        // A failed lazy import has no runtime resources to retain.
      }
      return;
    }

    const delegate = this.delegate;
    if (delegate !== undefined) {
      try {
        await delegate.dispose();
      } catch {
        // Runtime cleanup is contained at the renderer boundary.
      }
    }
  }

  private async loadDelegate(): Promise<Live2DEngine> {
    if (this.delegate !== undefined) {
      return this.delegate;
    }
    this.loading ??= Promise.resolve().then(() => {
      const delegate = createPixiCubism4Live2DEngine(this.config);
      this.delegate = delegate;
      return delegate;
    });
    return this.loading;
  }
}

const createDefaultEngine: Live2DEngineFactory = (config) =>
  new LazyPixiCubism4Engine(config);

/**
 * Internal Live2D adapter. It is intentionally absent from the body barrel
 * and current production body composition. BodyRendererHost remains the
 * canonical owner of render serialization; this adapter only owns the
 * Core/Pixi/model resource lifetime needed by the renderer contract.
 */
export class Live2DRenderer implements BodyRenderer {
  private readonly config: Live2DRendererConfig;
  private readonly engineFactory: Live2DEngineFactory;
  private phase: Live2DRendererPhase = "unmounted";
  private host: HTMLElement | undefined;
  private pendingMountHost: HTMLElement | undefined;
  private pendingMount: Promise<void> | undefined;
  private engine: Live2DEngine | undefined;
  private engineDisposal: Promise<void> | undefined;
  private lifecycleGeneration = 0;
  private disposePromise: Promise<void> | undefined;

  constructor(
    config: Live2DRendererConfig,
    engineFactory: Live2DEngineFactory = createDefaultEngine,
  ) {
    this.config = Object.freeze({
      modelUrl: config.modelUrl,
      coreReady: config.coreReady,
    });
    this.engineFactory = engineFactory;
  }

  isMounted(): boolean {
    return this.phase === "mounted";
  }

  async mount(host: HTMLElement): Promise<void> {
    if (this.phase === "disposed") {
      throw new BodyRendererError("Live2D renderer is disposed.");
    }
    if (this.phase === "mounted") {
      if (this.host === host) {
        return;
      }
      throw new BodyRendererError(
        "Live2D renderer is mounted to a different element.",
      );
    }
    if (this.phase === "mounting") {
      if (this.pendingMountHost === host && this.pendingMount !== undefined) {
        await this.pendingMount;
        return;
      }
      throw new BodyRendererError(
        "Live2D renderer is already mounting to a different element.",
      );
    }

    const generation = this.lifecycleGeneration + 1;
    this.lifecycleGeneration = generation;
    this.phase = "mounting";
    this.pendingMountHost = host;
    const mountPromise = this.mountFresh(host, generation);
    this.pendingMount = mountPromise;

    try {
      await mountPromise;
    } finally {
      if (this.pendingMount === mountPromise) {
        this.pendingMount = undefined;
        this.pendingMountHost = undefined;
      }
    }
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    await this.waitForMount();
    const engine = this.requireMountedEngine();
    try {
      await engine.render(snapshot);
    } catch (error) {
      if (error instanceof BodyRendererError) {
        throw error;
      }
      throw new BodyRendererError(RENDER_FAILURE_MESSAGE);
    }
  }

  /**
   * Internal layout hook for the later package composition. BodyRendererHost
   * remains responsible for serializing normal render deliveries; this method
   * only forwards a synchronous host-size update to the mounted engine.
   */
  async resize(): Promise<void> {
    await this.waitForMount();
    const engine = this.requireMountedEngine();
    try {
      engine.resize();
    } catch (error) {
      if (error instanceof BodyRendererError) {
        throw error;
      }
      throw new BodyRendererError(RESIZE_FAILURE_MESSAGE);
    }
  }

  async dispose(): Promise<void> {
    if (this.phase === "disposed") {
      await this.disposePromise;
      return;
    }

    const pendingMount = this.pendingMount;
    const ownedHost = this.host ?? this.pendingMountHost;
    this.phase = "disposed";
    this.lifecycleGeneration += 1;
    this.host = undefined;
    this.pendingMount = undefined;
    this.pendingMountHost = undefined;

    const disposal = (async () => {
      if (pendingMount !== undefined) {
        try {
          await pendingMount;
        } catch {
          // Mount failure is already converted to a bounded renderer error.
        }
      }
      await this.disposeEngine();
      this.clearOwnedHost(ownedHost);
    })();
    this.disposePromise = disposal;
    await disposal;
  }

  private async waitForMount(): Promise<void> {
    if (this.phase === "disposed") {
      throw new BodyRendererError("Live2D renderer is disposed.");
    }
    if (this.phase === "unmounted") {
      throw new BodyRendererError("Live2D renderer is not mounted.");
    }
    if (this.phase === "mounting") {
      const pendingMount = this.pendingMount;
      if (pendingMount === undefined) {
        throw new BodyRendererError("Live2D renderer is not mounted.");
      }
      try {
        await pendingMount;
      } catch {
        throw new BodyRendererError("Live2D renderer is not mounted.");
      }
      if (this.currentPhase() !== "mounted") {
        throw new BodyRendererError("Live2D renderer is not mounted.");
      }
    }
  }

  private requireMountedEngine(): Live2DEngine {
    if (this.phase !== "mounted" || this.engine === undefined) {
      throw new BodyRendererError("Live2D renderer is not mounted.");
    }
    return this.engine;
  }

  private currentPhase(): Live2DRendererPhase {
    return this.phase;
  }

  private async mountFresh(
    host: HTMLElement,
    generation: number,
  ): Promise<void> {
    try {
      const engine = this.engineFactory(this.config);
      this.engine = engine;
      await engine.mount(host, this.config.modelUrl);

      if (!this.isCurrentMount(generation)) {
        await this.disposeEngine();
        this.clearOwnedHost(host);
        return;
      }

      this.host = host;
      this.phase = "mounted";
    } catch (error) {
      await this.disposeEngine();
      this.clearOwnedHost(host);
      if (this.isCurrentMount(generation)) {
        this.phase = "unmounted";
        this.host = undefined;
      }
      if (error instanceof BodyRendererError) {
        throw error;
      }
      throw new BodyRendererError(MOUNT_FAILURE_MESSAGE);
    }
  }

  private async disposeEngine(): Promise<void> {
    const activeDisposal = this.engineDisposal;
    if (activeDisposal !== undefined) {
      await activeDisposal;
      return;
    }

    const engine = this.engine;
    if (engine === undefined) {
      return;
    }
    this.engine = undefined;

    let outcome: Promise<void> | void;
    try {
      outcome = engine.dispose();
    } catch {
      return;
    }

    const disposal = Promise.resolve(outcome).catch(() => undefined);
    this.engineDisposal = disposal;
    await disposal;
    if (this.engineDisposal === disposal) {
      this.engineDisposal = undefined;
    }
  }

  private isCurrentMount(generation: number): boolean {
    return (
      this.phase === "mounting" && this.lifecycleGeneration === generation
    );
  }

  private clearOwnedHost(host: HTMLElement | undefined): void {
    if (host === undefined) {
      return;
    }
    try {
      host.replaceChildren();
    } catch {
      // Renderer-local cleanup is best effort after a failed mount.
    }
  }
}
