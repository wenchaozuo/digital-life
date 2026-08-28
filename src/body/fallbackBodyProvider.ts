import type { BodyProvider, BodySnapshot, BodyState } from "./types.ts";

// D17-C primary/fallback body provider composition.
//
// The wrapper implements the existing `BodyProvider` contract.  A failing
// primary never propagates into presentation: the fallback supplies the
// requested state (never an invented idle).  A double failure surfaces as one
// bounded provider rejection for the application to contain; it never writes
// SQLite, never touches Conversation/Emotion/Relationship authority, and
// never terminates the application.

export class FallbackBodyProvider implements BodyProvider {
  /** The provider that last successfully supplied the rendered snapshot. */
  private readonly primary: BodyProvider;
  private readonly fallback: BodyProvider;
  private activeProvider: BodyProvider;

  constructor(primary: BodyProvider, fallback: BodyProvider) {
    this.primary = primary;
    this.fallback = fallback;
    // Before the first successful load the stable fallback current snapshot
    // is the deterministic presentation.
    this.activeProvider = fallback;
  }

  getCurrent(): BodySnapshot {
    return this.activeProvider.getCurrent();
  }

  async load(state: BodyState): Promise<BodySnapshot> {
    try {
      const snapshot = await this.primary.load(state);
      this.activeProvider = this.primary;
      return snapshot;
    } catch {
      // Primary failure is contained; the requested state is preserved.
    }
    const snapshot = await this.fallback.load(state);
    this.activeProvider = this.fallback;
    return snapshot;
  }

  async switchState(state: BodyState): Promise<BodySnapshot> {
    try {
      const snapshot = await this.primary.switchState(state);
      this.activeProvider = this.primary;
      return snapshot;
    } catch {
      // Primary failure is contained; the requested state is preserved.
    }
    const snapshot = await this.fallback.switchState(state);
    this.activeProvider = this.fallback;
    return snapshot;
  }
}