export const BODY_STATES = [
  "idle",
  "thinking",
  "speaking",
  "waiting",
  "error",
] as const;

export type BodyState = (typeof BODY_STATES)[number];

export interface BodyStateChange {
  previous: BodyState;
  current: BodyState;
  changedAt: number;
}

export interface BodySnapshot {
  resourcePath: string;
  state: BodyState;
}

export interface BodyProvider {
  getCurrent(): BodySnapshot;
  load(state: BodyState): Promise<BodySnapshot>;
  switchState(state: BodyState): Promise<BodySnapshot>;
}
