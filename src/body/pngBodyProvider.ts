import idleBodyResource from "../assets/body/digital-life-idle.png";
import type { BodyProvider, BodySnapshot, BodyState } from "./types.ts";

const resources: Record<BodyState, string> = {
  idle: idleBodyResource,
  thinking: idleBodyResource,
  speaking: idleBodyResource,
  waiting: idleBodyResource,
  error: idleBodyResource,
};

export class PngBodyProvider implements BodyProvider {
  private state: BodyState = "idle";

  getCurrent(): BodySnapshot {
    return {
      resourcePath: resources[this.state],
      state: this.state,
    };
  }

  async load(state: BodyState): Promise<BodySnapshot> {
    this.state = state;
    return this.getCurrent();
  }

  async switchState(state: BodyState): Promise<BodySnapshot> {
    this.state = state;
    return this.getCurrent();
  }
}
