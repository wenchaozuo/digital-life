import type { BodyProvider, BodySnapshot, BodyState } from "./types.ts";

// D17-C body render coordinator.
//
// Every requested render bumps an in-memory generation and fenced against
// stale completions: an awaited provider result whose token is no longer the
// current generation is never applied to the visible body resource/state.
// No Date.now token, no UUID, no persistence; `getCurrent()` returns the last
// applied snapshot (or the provider's deterministic current before the first
// successful render).

export interface BodyRenderResult {
  applied: boolean;
  snapshot: BodySnapshot;
}

export class BodyRenderCoordinator {
  private readonly provider: BodyProvider;
  private generation = 0;
  private applied: BodySnapshot | undefined;

  constructor(provider: BodyProvider) {
    this.provider = provider;
  }

  /** Last successfully applied snapshot, or the provider's current. */
  getCurrent(): BodySnapshot {
    if (this.applied !== undefined) {
      return this.applied;
    }
    return this.provider.getCurrent();
  }

  /**
   * Requests one fenced render.  `applied: true` means this result owns the
   * current generation and must be shown; `applied: false` means a newer
   * render superseded it and the caller must not update visible state.
   */
  async render(state: BodyState): Promise<BodyRenderResult> {
    this.generation += 1;
    const token = this.generation;
    const snapshot = await this.provider.switchState(state);
    if (token !== this.generation) {
      // Stale completion: a newer render was requested after this one started.
      return { applied: false, snapshot: this.getCurrent() };
    }
    this.applied = snapshot;
    return { applied: true, snapshot };
  }
}