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
 * Explicit lifecycle phases: `unmounted → mounting → mounted` and a terminal
 * `disposed`.  A single host-flag boolean is deliberately NOT the state
 * representation.
 *
 * - `mount`: transitions to `mounting`, awaits `renderer.mount(host)`, and
 *   only after successful completion remembers the host and becomes `mounted`.
 *   On mount rejection the host rolls back to `unmounted` (never a ghost
 *   mounted state) unless it was concurrently disposed.  A repeated mount of
 *   the SAME host is idempotent; while a mount is pending, a second mount of
 *   the same host awaits the SAME in-flight mount (the underlying renderer
 *   mount runs once), and a mount of a DIFFERENT host is a bounded
 *   `BodyRendererError`.
 * - `render`: while `mounting`, it WAITS for the same in-flight mount before
 *   rendering (so the first valid snapshot is never dropped and
 *   `renderer.render` can never run before `renderer.mount` completes).  In
 *   `unmounted`/`disposed` it rejects with a bounded `BodyRendererError`.
 * - `dispose`: terminal and safe to repeat.  If dispose happens while a
 *   mount is pending, the completed (or failed) mount's renderer resources
 *   are disposed exactly once afterwards — the host never resurrects.
 *   Async dispose rejections are contained and never become unhandled.
 */
export class BodyRendererHost {
  private readonly renderer: BodyRenderer;
  private phase: "unmounted" | "mounting" | "mounted" | "disposed" = "unmounted";
  private host: HTMLElement | undefined;
  private pendingMount: Promise<void> | undefined;
  private pendingMountHost: HTMLElement | undefined;

  constructor(renderer: BodyRenderer) {
    this.renderer = renderer;
  }

  mounted(): boolean {
    return this.phase === "mounted";
  }

  async mount(host: HTMLElement): Promise<void> {
    if (this.phase === "disposed") {
      throw new BodyRendererError("renderer host is disposed.");
    }
    if (this.phase === "mounted") {
      if (this.host === host) {
        return; // Idempotent: already mounted to this exact host.
      }
      throw new BodyRendererError(
        "renderer host is already mounted to a different element.",
      );
    }
    if (this.phase === "mounting") {
      if (host === this.pendingMountHost) {
        // Same host, same in-flight mount: await the identical result.
        await this.pendingMount;
        return;
      }
      throw new BodyRendererError(
        "renderer host is already mounting to a different element.",
      );
    }

    this.phase = "mounting";
    this.pendingMountHost = host;
    const mountResult = Promise.resolve(this.renderer.mount(host));
    const sealedMount = mountResult.then(
      () => {
        if (this.phase === "disposed") {
          // Disposed while mounting: no resurrection; the dispose chain owns
          // cleanup of anything the completed mount created.
          return;
        }
        this.host = host;
        this.phase = "mounted";
      },
      (error: unknown) => {
        if (this.phase !== "disposed") {
          // Mount failure rollback: return to unmounted so a later retry is
          // possible and no ghost mounted state remains.
          this.pendingMount = undefined;
          this.pendingMountHost = undefined;
          this.phase = "unmounted";
        }
        throw error;
      },
    );
    this.pendingMount = sealedMount;
    await sealedMount;
  }

  async render(snapshot: BodySnapshot): Promise<void> {
    if (this.phase === "disposed") {
      throw new BodyRendererError("renderer host is disposed.");
    }
    if (this.phase === "unmounted") {
      throw new BodyRendererError("renderer host is not mounted.");
    }
    if (this.phase === "mounting") {
      // Wait for the SAME in-flight mount: render never executes before
      // renderer.mount completes, and the first valid snapshot is not lost.
      try {
        await this.pendingMount;
      } catch {
        throw new BodyRendererError("renderer host is not mounted.");
      }
      // Observe the settled phase through the accessor: the mount settle
      // chain leaves only `mounted` or `disposed` behind, and a method read
      // is never stale-narrowed across the await.
      if (this.currentPhase() !== "mounted") {
        throw new BodyRendererError("renderer host is not mounted.");
      }
    }
    await this.renderer.render(snapshot);
  }

  private currentPhase(): "unmounted" | "mounting" | "mounted" | "disposed" {
    return this.phase;
  }

  dispose(): void {
    if (this.phase === "disposed") {
      return;
    }
    if (this.phase === "mounting") {
      // Dispose during a pending mount: the mounted-phase check must never
      // resurrect the renderer, and whatever the completed or failed mount
      // created is disposed exactly once once the in-flight mount settles.
      const pendingMount = this.pendingMount;
      this.phase = "disposed";
      this.host = undefined;
      this.pendingMount = undefined;
      this.pendingMountHost = undefined;
      if (pendingMount !== undefined) {
        void pendingMount.then(
          () => {
            void Promise.resolve(this.renderer.dispose()).catch(() => {
              // Async dispose rejection is contained.
            });
          },
          () => {
            void Promise.resolve(this.renderer.dispose()).catch(() => {
              // Async dispose rejection is contained.
            });
          },
        );
      }
      return;
    }
    this.phase = "disposed";
    this.host = undefined;
    void Promise.resolve(this.renderer.dispose()).catch(() => {
      // Async dispose rejection is contained.
    });
  }
}