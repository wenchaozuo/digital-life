import type { BodySnapshot } from "./types.ts";

// D18-B1 renderer-neutral body presentation contract.
//
// `BodyProvider` remains the static resource resolver (unchanged D17 role);
// this module separates actual DOM renderer ownership from state/resource
// resolution.  The contract is deliberately renderer-neutral: no model,
// canvas, motion, physics, or Live2D-specific method exists.  Renderer
// instances belong ONLY to the main WebView; chat/settings never instantiate
// one.

/** Narrow bounded presentation-layer error for renderer lifecycle misuse. */
export class BodyRendererError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BodyRendererError";
  }
}

/**
 * Renderer-neutral contract.  Implementations operate only inside their
 * supplied host element: no global document queries, no element-ID
 * singletons, no global document append.
 */
export interface BodyRenderer {
  mount(host: HTMLElement): Promise<void> | void;
  render(snapshot: BodySnapshot): Promise<void> | void;
  dispose(): Promise<void> | void;
}

/**
 * Small main-owned lifecycle owner for exactly one renderer.
 *
 * - `mount`: once, onto the host element; a repeated mount of the SAME host
 *   is an idempotent no-op, a mount onto a DIFFERENT host while already
 *   mounted is a bounded `BodyRendererError` (never a silent second tree).
 * - `render`: forwards to the mounted renderer; before mount it rejects with
 *   a bounded `BodyRendererError`.
 * - `dispose`: disposes the renderer exactly once; repeated disposal is a
 *   safe no-op.
 */
export class BodyRendererHost {
  private readonly renderer: BodyRenderer;
  private host: HTMLElement | undefined;
  private disposed = false;

  constructor(renderer: BodyRenderer) {
    this.renderer = renderer;
  }

  mounted(): boolean {
    return this.host !== undefined;
  }

  async mount(host: HTMLElement): Promise<void> {
    if (this.disposed) {
      throw new BodyRendererError("renderer host is disposed.");
    }
    if (this.host === host) {
      return; // Idempotent: already mounted to this exact host.
    }
    if (this.host !== undefined) {
      throw new BodyRendererError(
        "renderer host is already mounted to a different element.",
      );
    }
    this.host = host;
    await this.renderer.mount(host);
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    if (this.disposed) {
      throw new BodyRendererError("renderer host is disposed.");
    }
    if (this.host === undefined) {
      throw new BodyRendererError("renderer host is not mounted.");
    }
    await this.renderer.render(snapshot);
  }

  dispose(): void {
    if (this.disposed) {
      return;
    }
    this.disposed = true;
    this.host = undefined;
    void this.renderer.dispose();
  }
}