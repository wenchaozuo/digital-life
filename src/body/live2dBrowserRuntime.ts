import { Application } from "pixi.js";
import { Live2DModel } from "@jannchie/pixi-live2d-display/cubism4";

import { BodyRendererError } from "./bodyRenderer.ts";
import type { BodySnapshot } from "./types.ts";

export interface Live2DBrowserRendererConfig {
  readonly modelUrl: string;
}

export interface Live2DBrowserEngine {
  mount(host: HTMLElement, modelUrl: string): Promise<void>;
  render(snapshot: BodySnapshot): Promise<void> | void;
  dispose(): Promise<void> | void;
}

export type Live2DBrowserEngineFactory = (
  config: Live2DBrowserRendererConfig,
) => Live2DBrowserEngine;

const LIVE2D_ENGINE_MOUNT_ERROR = "Live2D browser engine mount failed.";

/**
 * The concrete D21 browser-only engine.  It is deliberately kept behind the
 * internal engine seam so the lifecycle contract can be tested without WebGL.
 */
class PixiCubism4BrowserEngine implements Live2DBrowserEngine {
  private app: Application | undefined;
  private model: Live2DModel | undefined;
  private host: HTMLElement | undefined;
  private canvas: HTMLCanvasElement | undefined;
  private disposed = false;

  async mount(host: HTMLElement, modelUrl: string): Promise<void> {
    if (this.disposed || this.app !== undefined) {
      throw new BodyRendererError(LIVE2D_ENGINE_MOUNT_ERROR);
    }

    this.host = host;
    const app = new Application();
    this.app = app;

    try {
      await app.init({
        width: Math.max(host.clientWidth, 1),
        height: Math.max(host.clientHeight, 1),
        antialias: true,
        backgroundAlpha: 0,
        autoStart: false,
        sharedTicker: false,
        preference: "webgl",
      });

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
      });

      if (this.disposed) {
        this.destroyModel(model);
        return;
      }

      this.model = model;
      app.stage.addChild(model);
      model.anchor.set(0.5, 1);
      model.x = app.screen.width / 2;
      model.y = app.screen.height;
      model.visible = true;
      canvas.dataset.live2dReady = "true";
      app.start();
      app.render();
    } catch (error) {
      this.dispose();
      throw error;
    }
  }

  render(snapshot: BodySnapshot): void {
    const model = this.model;
    if (this.disposed || model === undefined) {
      throw new BodyRendererError("Live2D browser engine is not mounted.");
    }

    // B1-R1 intentionally has no motion or emotion mapping.  The state is
    // retained as presentation metadata while the model source stays fixed
    // in the constructor configuration.
    model.visible = true;
    const canvas = this.canvas;
    if (canvas !== undefined) {
      canvas.dataset.live2dState = snapshot.state;
      canvas.setAttribute("aria-label", `Digital Life ${snapshot.state} body`);
    }
  }

  dispose(): void {
    if (this.disposed && this.app === undefined && this.model === undefined) {
      return;
    }

    this.disposed = true;
    const model = this.model;
    const app = this.app;
    const host = this.host;
    const canvas = this.canvas;
    this.model = undefined;
    this.app = undefined;
    this.host = undefined;
    this.canvas = undefined;

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
      canvas.remove();
    }
    if (host !== undefined) {
      host.replaceChildren();
    }
  }

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

export function createPixiCubism4BrowserEngine(
  _config: Live2DBrowserRendererConfig,
): Live2DBrowserEngine {
  return new PixiCubism4BrowserEngine();
}
