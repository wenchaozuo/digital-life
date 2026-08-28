import { BodyRendererError } from "./bodyRenderer.ts";
import type { BodyRenderer } from "./bodyRenderer.ts";
import type {
  Live2DBrowserEngine,
  Live2DBrowserEngineFactory,
  Live2DBrowserRendererConfig,
} from "./live2dBrowserRuntime.ts";
import type { BodySnapshot } from "./types.ts";

export type {
  Live2DBrowserEngine,
  Live2DBrowserEngineFactory,
  Live2DBrowserRendererConfig,
} from "./live2dBrowserRuntime.ts";

type Live2DRendererPhase =
  | "unmounted"
  | "mounting"
  | "mounted"
  | "disposed";

const MOUNT_FAILURE_MESSAGE = "Live2D test renderer mount failed.";

/**
 * Keep the Core-dependent concrete module out of non-browser unit-test
 * collection.  A real smoke mount loads it only after the page supplied the
 * official Cubism Core script.
 */
class LazyPixiCubism4Engine implements Live2DBrowserEngine {
  private readonly config: Live2DBrowserRendererConfig;
  private delegate: Live2DBrowserEngine | undefined;
  private loading: Promise<Live2DBrowserEngine> | undefined;

  constructor(config: Live2DBrowserRendererConfig) {
    this.config = config;
  }

  async mount(host: HTMLElement, modelUrl: string): Promise<void> {
    const delegate = await this.loadDelegate();
    await delegate.mount(host, modelUrl);
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    const delegate = this.delegate;
    if (delegate === undefined) {
      throw new BodyRendererError("Live2D browser engine is not mounted.");
    }
    await delegate.render(snapshot);
  }

  async dispose(): Promise<void> {
    const delegate = this.delegate;
    if (delegate !== undefined) {
      await delegate.dispose();
      return;
    }
    const loading = this.loading;
    if (loading !== undefined) {
      try {
        await (await loading).dispose();
      } catch {
        // A failed lazy import has no runtime resources to retain.
      }
    }
  }

  private async loadDelegate(): Promise<Live2DBrowserEngine> {
    if (this.delegate !== undefined) {
      return this.delegate;
    }
    this.loading ??= import("./live2dBrowserRuntime.ts").then((module) => {
      const delegate = module.createPixiCubism4BrowserEngine(this.config);
      this.delegate = delegate;
      return delegate;
    });
    return this.loading;
  }
}

const createDefaultEngine: Live2DBrowserEngineFactory = (config) =>
  new LazyPixiCubism4Engine(config);

/**
 * Internal D21 feasibility renderer.  It is not exported through the body
 * barrel and is not part of the production body package composition.
 */
export class Live2DBrowserTestRenderer implements BodyRenderer {
  private readonly config: Live2DBrowserRendererConfig;
  private readonly engineFactory: Live2DBrowserEngineFactory;
  private phase: Live2DRendererPhase = "unmounted";
  private host: HTMLElement | undefined;
  private pendingMountHost: HTMLElement | undefined;
  private pendingMount: Promise<void> | undefined;
  private engine: Live2DBrowserEngine | undefined;
  private engineDisposal: Promise<void> | undefined;
  private renderTail: Promise<void> = Promise.resolve();
  private lifecycleGeneration = 0;
  private disposePromise: Promise<void> | undefined;

  constructor(
    config: Live2DBrowserRendererConfig,
    engineFactory: Live2DBrowserEngineFactory = createDefaultEngine,
  ) {
    this.config = { modelUrl: config.modelUrl };
    this.engineFactory = engineFactory;
  }

  isMounted(): boolean {
    return this.phase === "mounted";
  }

  async mount(host: HTMLElement): Promise<void> {
    if (this.phase === "disposed") {
      throw new BodyRendererError("Live2D test renderer is disposed.");
    }
    if (this.phase === "mounted") {
      if (this.host === host) {
        return;
      }
      throw new BodyRendererError(
        "Live2D test renderer is mounted to a different element.",
      );
    }
    if (this.phase === "mounting") {
      if (this.pendingMountHost === host && this.pendingMount !== undefined) {
        await this.pendingMount;
        return;
      }
      throw new BodyRendererError(
        "Live2D test renderer is already mounting to a different element.",
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
    if (this.phase === "disposed") {
      throw new BodyRendererError("Live2D test renderer is disposed.");
    }
    if (this.phase === "unmounted") {
      throw new BodyRendererError("Live2D test renderer is not mounted.");
    }
    if (this.phase === "mounting") {
      const pendingMount = this.pendingMount;
      if (pendingMount === undefined) {
        throw new BodyRendererError("Live2D test renderer is not mounted.");
      }
      try {
        await pendingMount;
      } catch {
        throw new BodyRendererError("Live2D test renderer is not mounted.");
      }
      if (this.currentPhase() !== "mounted") {
        throw new BodyRendererError("Live2D test renderer is not mounted.");
      }
    }

    return this.enqueueRender(snapshot);
  }

  async dispose(): Promise<void> {
    if (this.phase === "disposed") {
      await this.disposePromise;
      return;
    }

    const pendingMount = this.pendingMount;
    const ownedHost = this.host ?? this.pendingMountHost;
    const renderTail = this.renderTail;
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
      await renderTail;
      await this.disposeEngine();
      this.clearOwnedHost(ownedHost);
    })();
    this.disposePromise = disposal;
    await disposal;
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
    } catch {
      await this.disposeEngine();
      this.clearOwnedHost(host);
      if (this.isCurrentMount(generation)) {
        this.phase = "unmounted";
        this.host = undefined;
      }
      throw new BodyRendererError(MOUNT_FAILURE_MESSAGE);
    }
  }

  private enqueueRender(snapshot: BodySnapshot): Promise<void> {
    const execution = this.renderTail
      .then(() => {
        if (this.phase !== "mounted") {
          throw new BodyRendererError("Live2D test renderer is not mounted.");
        }
        const engine = this.engine;
        if (engine === undefined) {
          throw new BodyRendererError("Live2D test renderer is not mounted.");
        }
        return Promise.resolve(engine.render(snapshot));
      })
      .finally(() => undefined);

    this.renderTail = execution.catch(() => undefined);
    return execution;
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

  private currentPhase(): Live2DRendererPhase {
    return this.phase;
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
