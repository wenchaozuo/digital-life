import {
  copyValidatedPngBodyResources,
  DEFAULT_BUNDLED_PNG_RESOURCES,
  type PngBodyResources,
} from "./pngBodyResources.ts";
import type { BodyProvider, BodySnapshot, BodyState } from "./types.ts";

export class PngBodyProvider implements BodyProvider {
  private readonly resources: PngBodyResources;
  private state: BodyState = "idle";

  constructor(resources: PngBodyResources = DEFAULT_BUNDLED_PNG_RESOURCES) {
    this.resources = copyValidatedPngBodyResources(resources);
  }

  getCurrent(): BodySnapshot {
    return {
      resourcePath: this.resources[this.state],
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
