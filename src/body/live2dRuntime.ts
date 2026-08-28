import { Application } from "pixi.js";
import type { Live2DModel } from "@jannchie/pixi-live2d-display/cubism4";

import { BodyRendererError } from "./bodyRenderer.ts";
import type { BodySnapshot } from "./types.ts";

const MIN_RENDER_SIZE = 1;
const FIT_MARGIN_RATIO = 0.04;
const MOUNT_FAILURE_MESSAGE = "Live2D renderer mount failed.";
const RESIZE_FAILURE_MESSAGE = "Live2D renderer resize failed.";

export const LIVE2D_CORE_UNAVAILABLE_MESSAGE =
  "Live2D Cubism Core is not ready.";
export const LIVE2D_CORE_STARTUP_FAILURE_MESSAGE =
  "Live2D Cubism Core startup failed.";

interface WindowWithCubismCore extends Window {
  Live2DCubismCore?: unknown;
}

/**
 * Explicit prerequisite for the proprietary Cubism Core runtime.
 * Production callers must provide a boundary that is already authorized to
 * make Core available; this module never downloads or injects Core itself.
 */
export interface Live2DCoreReadyBoundary {
  ensureReady(): Promise<void> | void;
}

export interface Live2DRendererConfig {
  readonly modelUrl: string;
  readonly coreReady: Live2DCoreReadyBoundary;
}

export interface Live2DEngine {
  mount(host: HTMLElement, modelUrl: string): Promise<void>;
  resize(): void;
  render(snapshot: BodySnapshot): Promise<void> | void;
  dispose(): Promise<void> | void;
}

export type Live2DEngineFactory = (
  config: Live2DRendererConfig,
) => Live2DEngine;

export class Live2DCoreUnavailableError extends BodyRendererError {
  constructor() {
    super(LIVE2D_CORE_UNAVAILABLE_MESSAGE);
    this.name = "Live2DCoreUnavailableError";
  }
}

export class Live2DCoreStartupError extends BodyRendererError {
  constructor() {
    super(LIVE2D_CORE_STARTUP_FAILURE_MESSAGE);
    this.name = "Live2DCoreStartupError";
  }
}

export interface Live2DViewportSize {
  readonly width: number;
  readonly height: number;
}

export interface Live2DModelSize {
  readonly width: number;
  readonly height: number;
}

export interface Live2DModelLayout {
  readonly scale: number;
  readonly x: number;
  readonly y: number;
}

function safeDimension(value: number): number {
  if (!Number.isFinite(value) || value <= 0) {
    return MIN_RENDER_SIZE;
  }
  return Math.max(MIN_RENDER_SIZE, Math.round(value));
}

function safeModelDimension(value: number): number {
  return Number.isFinite(value) && value > 0 ? value : MIN_RENDER_SIZE;
}

export function normalizeLive2DHostSize(
  width: number,
  height: number,
): Live2DViewportSize {
  return {
    width: safeDimension(width),
    height: safeDimension(height),
  };
}

export function measureLive2DHost(host: HTMLElement): Live2DViewportSize {
  const bounds = host.getBoundingClientRect();
  const width = bounds.width > 0 ? bounds.width : host.clientWidth;
  const height = bounds.height > 0 ? bounds.height : host.clientHeight;
  return normalizeLive2DHostSize(width, height);
}

/**
 * Calculates a stable contain-style presentation with a bottom-center anchor.
 * The minimum dimensions keep Pixi valid even while a host is hidden or has
 * not received layout yet.
 */
export function calculateLive2DModelLayout(
  viewport: Live2DViewportSize,
  model: Live2DModelSize,
): Live2DModelLayout {
  const width = safeDimension(viewport.width);
  const height = safeDimension(viewport.height);
  const modelWidth = safeModelDimension(model.width);
  const modelHeight = safeModelDimension(model.height);
  const horizontalInset = width * FIT_MARGIN_RATIO;
  const verticalInset = height * FIT_MARGIN_RATIO;
  const availableWidth = Math.max(MIN_RENDER_SIZE, width - horizontalInset * 2);
  const availableHeight = Math.max(MIN_RENDER_SIZE, height - verticalInset);
  const scale = Math.min(
    availableWidth / modelWidth,
    availableHeight / modelHeight,
  );

  return {
    scale: Number.isFinite(scale) && scale > 0 ? scale : 1,
    x: width / 2,
    y: height,
  };
}

function hasCubismCore(): boolean {
  return (
    typeof window !== "undefined" &&
    (window as WindowWithCubismCore).Live2DCubismCore !== undefined
  );
}

/**
 * Default local readiness boundary. It observes an already supplied Core
 * runtime and starts the Cubism4 framework, but it has no network or script
 * injection behavior. The B1 smoke page supplies Core separately.
 */
export function createLive2DCoreReadyBoundary(): Live2DCoreReadyBoundary {
  return {
    async ensureReady(): Promise<void> {
      if (!hasCubismCore()) {
        throw new Live2DCoreUnavailableError();
      }

      try {
        const cubism4 = await import(
          "@jannchie/pixi-live2d-display/cubism4"
        );
        await cubism4.cubism4Ready();
      } catch (error) {
        if (error instanceof Live2DCoreUnavailableError) {
          throw error;
        }
        throw new Live2DCoreStartupError();
      }
    },
  };
}

class PixiCubism4Live2DEngine implements Live2DEngine {
  private readonly config: Live2DRendererConfig;
  private app: Application | undefined;
  private model: Live2DModel | undefined;
  private host: HTMLElement | undefined;
  private canvas: HTMLCanvasElement | undefined;
  private modelSize: Live2DModelSize | undefined;
  private resizeObserver: ResizeObserver | undefined;
  private usingWindowResize = false;
  private disposed = false;

  constructor(config: Live2DRendererConfig) {
    this.config = config;
  }

  async mount(host: HTMLElement, modelUrl: string): Promise<void> {
    if (this.disposed || this.app !== undefined) {
      throw new BodyRendererError(MOUNT_FAILURE_MESSAGE);
    }

    // The Core prerequisite is checked before the Pixi application or model
    // is allocated. This is the production boundary; no remote Core fetch is
    // reachable from this module.
    await this.config.coreReady.ensureReady();
    if (this.disposed) {
      return;
    }

    const { Live2DModel } = await import(
      "@jannchie/pixi-live2d-display/cubism4"
    );
    if (this.disposed) {
      return;
    }

    const app = new Application();
    this.app = app;
    this.host = host;

    try {
      const viewport = measureLive2DHost(host);
      await app.init({
        width: viewport.width,
        height: viewport.height,
        antialias: true,
        backgroundAlpha: 0,
        autoStart: false,
        sharedTicker: false,
        preference: "webgl",
      });

      if (this.disposed) {
        return;
      }

      const canvas = app.canvas as HTMLCanvasElement;
      this.canvas = canvas;
      canvas.dataset.live2dRenderer = "cubism4";
      canvas.style.display = "block";
      canvas.style.width = "100%";
      canvas.style.height = "100%";
      host.replaceChildren(canvas);

      const model = await Live2DModel.from(modelUrl, {
        ticker: app.ticker,
        autoUpdate: true,
        autoHitTest: false,
        autoFocus: false,
        autoTransition: false,
      });

      if (this.disposed) {
        this.destroyModel(model);
        return;
      }

      this.model = model;
      app.stage.addChild(model);
      model.anchor.set(0.5, 1);
      this.modelSize = this.measureModel(model);
      canvas.dataset.live2dFit = "contain-bottom-center";
      canvas.dataset.live2dReady = "true";
      app.start();
      this.resize();
      this.installResizeObservation(host);
      app.render();
    } catch (error) {
      this.dispose();
      if (error instanceof BodyRendererError) {
        throw error;
      }
      throw new BodyRendererError(MOUNT_FAILURE_MESSAGE);
    }
  }

  resize(): void {
    if (this.disposed) {
      return;
    }

    const app = this.app;
    const host = this.host;
    if (app === undefined || host === undefined) {
      return;
    }

    try {
      const viewport = measureLive2DHost(host);
      app.renderer.resize(viewport.width, viewport.height);
      const canvas = this.canvas;
      if (canvas !== undefined) {
        canvas.dataset.live2dWidth = String(viewport.width);
        canvas.dataset.live2dHeight = String(viewport.height);
      }

      const model = this.model;
      const modelSize = this.modelSize;
      if (model !== undefined && modelSize !== undefined) {
        const layout = calculateLive2DModelLayout(viewport, modelSize);
        model.scale.set(layout.scale);
        model.position.set(layout.x, layout.y);
        if (canvas !== undefined) {
          canvas.dataset.live2dModelScale = String(layout.scale);
          canvas.dataset.live2dModelX = String(layout.x);
          canvas.dataset.live2dModelY = String(layout.y);
        }
      }
      app.render();
    } catch {
      throw new BodyRendererError(RESIZE_FAILURE_MESSAGE);
    }
  }

  render(snapshot: BodySnapshot): void {
    const model = this.model;
    if (this.disposed || model === undefined) {
      throw new BodyRendererError("Live2D renderer is not mounted.");
    }

    // Body state remains bounded presentation metadata until the later
    // motion/expression stage. No motion, audio, or lip-sync is started here.
    model.visible = true;
    const canvas = this.canvas;
    if (canvas !== undefined) {
      canvas.dataset.live2dState = snapshot.state;
      canvas.setAttribute("aria-label", `Digital Life ${snapshot.state} body`);
    }
  }

  dispose(): void {
    if (
      this.disposed &&
      this.app === undefined &&
      this.model === undefined &&
      this.resizeObserver === undefined
    ) {
      return;
    }

    this.disposed = true;
    this.resizeObserver?.disconnect();
    this.resizeObserver = undefined;
    if (this.usingWindowResize && typeof window !== "undefined") {
      window.removeEventListener("resize", this.onWindowResize);
    }
    this.usingWindowResize = false;

    const model = this.model;
    const app = this.app;
    const host = this.host;
    const canvas = this.canvas;
    this.model = undefined;
    this.app = undefined;
    this.host = undefined;
    this.canvas = undefined;
    this.modelSize = undefined;

    if (model !== undefined) {
      this.destroyModel(model);
    }
    if (app !== undefined) {
      try {
        app.stop();
        app.destroy(true, true);
      } catch {
        // Partial Pixi initialization is best-effort cleaned up.
      }
    }
    if (canvas !== undefined && canvas.parentElement === host) {
      try {
        canvas.remove();
      } catch {
        // Host cleanup below remains the final renderer-local fence.
      }
    }
    if (host !== undefined) {
      try {
        host.replaceChildren();
      } catch {
        // Cleanup failure must not escape the renderer boundary.
      }
    }
  }

  private measureModel(model: Live2DModel): Live2DModelSize {
    try {
      const bounds = model.getLocalBounds();
      if (bounds.width > 0 && bounds.height > 0) {
        return { width: bounds.width, height: bounds.height };
      }
    } catch {
      // Fall through to the library-provided model dimensions.
    }

    return {
      width: safeModelDimension(model.internalModel?.width ?? model.width),
      height: safeModelDimension(model.internalModel?.height ?? model.height),
    };
  }

  private installResizeObservation(host: HTMLElement): void {
    if (typeof ResizeObserver !== "undefined") {
      const observer = new ResizeObserver(() => {
        try {
          this.resize();
        } catch {
          // ResizeObserver callbacks cannot expose renderer errors as an
          // unhandled rejection or uncaught asynchronous exception.
        }
      });
      observer.observe(host);
      this.resizeObserver = observer;
      return;
    }

    if (typeof window !== "undefined") {
      window.addEventListener("resize", this.onWindowResize);
      this.usingWindowResize = true;
    }
  }

  private readonly onWindowResize = (): void => {
    try {
      this.resize();
    } catch {
      // Window resize is a best-effort presentation update.
    }
  };

  private destroyModel(model: Live2DModel): void {
    try {
      model.automator.autoUpdate = false;
    } catch {
      // A model that failed before its automator was ready is still retired
      // by the bounded destroy attempt below.
    }
    try {
      model.parent?.removeChild(model);
      model.destroy({
        children: true,
        texture: true,
        textureSource: true,
      });
    } catch {
      // Model cleanup must not mask the original mount/dispose outcome.
    }
  }
}

export function createPixiCubism4Live2DEngine(
  config: Live2DRendererConfig,
): Live2DEngine {
  return new PixiCubism4Live2DEngine(config);
}
