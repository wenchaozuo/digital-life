import type { BodyState, BodyStateChange } from "./types";

type BodyStateListener = (change: BodyStateChange) => void;

export class BodyStateMachine {
  private currentState: BodyState;
  private readonly listeners = new Set<BodyStateListener>();
  private readonly history: BodyStateChange[] = [];

  constructor(initialState: BodyState = "idle", private readonly historyLimit = 20) {
    this.currentState = initialState;
  }

  getState(): BodyState {
    return this.currentState;
  }

  getHistory(): readonly BodyStateChange[] {
    return this.history;
  }

  transition(nextState: BodyState): BodyStateChange | undefined {
    if (nextState === this.currentState) {
      return undefined;
    }

    const change: BodyStateChange = {
      previous: this.currentState,
      current: nextState,
      changedAt: Date.now(),
    };

    this.currentState = nextState;
    this.history.push(change);
    if (this.history.length > this.historyLimit) {
      this.history.shift();
    }

    this.listeners.forEach((listener) => listener(change));
    return change;
  }

  subscribe(listener: BodyStateListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }
}
