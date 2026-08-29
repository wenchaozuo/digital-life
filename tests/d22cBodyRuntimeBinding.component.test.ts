import { describe, expect, it } from "vitest";

import { BodyRuntimeBindingController } from "../src/body";
import type { BodyPresentationComposition } from "../src/body/bodyBinding";
import type { BodyProvider, BodySnapshot, BodyState } from "../src/body/types";
import type { InstalledBodyPackageSnapshot } from "../src/body/bodyPackageService";
import type { LifeIdentity } from "../src/life/lifeIdentity";
import type { BodyRenderer } from "../src/body/bodyRenderer";

class Deferred<T> {
  readonly promise: Promise<T>;
  resolve!: (value: T | PromiseLike<T>) => void;

  constructor() {
    this.promise = new Promise<T>((resolve) => {
      this.resolve = resolve;
    });
  }
}

class ImmediateProvider implements BodyProvider {
  readonly states: BodyState[] = [];

  async switchState(state: BodyState): Promise<BodySnapshot> {
    this.states.push(state);
    return { resourcePath: `${state}.png`, state };
  }

  async load(state: BodyState): Promise<BodySnapshot> {
    return this.switchState(state);
  }

  getCurrent(): BodySnapshot {
    return { resourcePath: "idle.png", state: "idle" };
  }
}

class RecordingRenderer implements BodyRenderer {
  readonly mounted: HTMLElement[] = [];
  readonly rendered: BodySnapshot[] = [];
  disposeCalls = 0;
  private readonly mountGate?: Deferred<void>;
  private host: HTMLElement | undefined;

  constructor(private readonly bodyId: string, mountGate?: Deferred<void>) {
    this.mountGate = mountGate;
  }

  async mount(host: HTMLElement): Promise<void> {
    if (this.mountGate !== undefined) {
      await this.mountGate.promise;
    }
    this.mounted.push(host);
    this.host = host;
    const marker = document.createElement("span");
    marker.dataset.bodyId = this.bodyId;
    host.append(marker);
  }

  render(snapshot: BodySnapshot): void {
    this.rendered.push(snapshot);
  }

  dispose(): void {
    this.disposeCalls += 1;
    this.host?.replaceChildren();
  }
}

class AsyncDisposingRenderer implements BodyRenderer {
  readonly rendered: BodySnapshot[] = [];
  readonly disposeGate = new Deferred<void>();
  disposeCalls = 0;
  private host: HTMLElement | undefined;

  async mount(host: HTMLElement): Promise<void> {
    this.host = host;
    const marker = document.createElement("span");
    marker.dataset.bodyId = "async-dispose";
    host.append(marker);
  }

  render(snapshot: BodySnapshot): void {
    this.rendered.push(snapshot);
  }

  async dispose(): Promise<void> {
    this.disposeCalls += 1;
    await this.disposeGate.promise;
    this.host?.replaceChildren();
  }
}

function life(bodyId: string): LifeIdentity {
  return {
    id: "life-1",
    name: "Life",
    createdAt: "2026-08-29T00:00:00.000Z",
    version: 1,
    bodyId,
    personaId: "persona-1",
    personaVersion: 1,
  };
}

function emptyRegistry(): readonly InstalledBodyPackageSnapshot[] {
  return [];
}

async function flushMicrotasks(rounds = 20): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

describe("D22-C Main body runtime binding controller", () => {
  it("loads registry before Life initialization and renders the current machine state", async () => {
    const order: string[] = [];
    let currentState: BodyState = "thinking";
    const renderer = new RecordingRenderer("default-png");
    const provider = new ImmediateProvider();
    const composition: BodyPresentationComposition = { provider, renderer };
    const controller = new BodyRuntimeBindingController({
      loadRegistrySnapshot: async () => {
        order.push("registry-read");
        return emptyRegistry();
      },
      installRegistrySnapshot: () => order.push("registry-install"),
      loadCurrentLife: async () => life("default-png"),
      createPresentation: (bodyId) => {
        order.push(`presentation:${bodyId}`);
        return composition;
      },
      getCurrentState: () => currentState,
      onSnapshot: (snapshot) => order.push(`snapshot:${snapshot.state}`),
    });
    const host = document.createElement("div");

    const initialized = await controller.initialize(host, async () => {
      order.push("life-init");
      return life("default-png");
    });

    expect(initialized?.bodyId).toBe("default-png");
    expect(order).toEqual([
      "registry-read",
      "registry-install",
      "life-init",
      "presentation:default-png",
      "snapshot:thinking",
    ]);
    expect(provider.states).toEqual(["thinking"]);
    expect(renderer.rendered).toEqual([
      { resourcePath: "thinking.png", state: "thinking" },
    ]);
    expect(controller.currentBodyId).toBe("default-png");
    controller.dispose();
  });

  it("continues Life startup with a default-only install when registry loading fails", async () => {
    const installedSnapshots: InstalledBodyPackageSnapshot[][] = [];
    let presentations = 0;
    const controller = new BodyRuntimeBindingController({
      loadRegistrySnapshot: async () => {
        throw new Error("registry unavailable");
      },
      installRegistrySnapshot: (snapshots) => {
        installedSnapshots.push([...snapshots]);
      },
      loadCurrentLife: async () => life("unknown-persisted-body"),
      createPresentation: () => {
        presentations += 1;
        return {
          provider: new ImmediateProvider(),
          renderer: new RecordingRenderer("default-png"),
        };
      },
      getCurrentState: () => "idle",
    });

    const initialized = await controller.initialize(
      document.createElement("div"),
      async () => life("unknown-persisted-body"),
    );

    expect(initialized?.bodyId).toBe("unknown-persisted-body");
    expect(installedSnapshots).toEqual([[]]);
    expect(presentations).toBe(1);
    controller.dispose();
  });

  it("rebinds PNG and managed presentations without resetting the current state", async () => {
    const host = document.createElement("div");
    let currentLife = life("default-png");
    let currentState: BodyState = "thinking";
    const providers: ImmediateProvider[] = [];
    const renderers: RecordingRenderer[] = [];
    const controller = new BodyRuntimeBindingController({
      loadRegistrySnapshot: async () => emptyRegistry(),
      installRegistrySnapshot: () => undefined,
      loadCurrentLife: async () => currentLife,
      createPresentation: (bodyId) => {
        const provider = new ImmediateProvider();
        const renderer = new RecordingRenderer(bodyId);
        providers.push(provider);
        renderers.push(renderer);
        return { provider, renderer };
      },
      getCurrentState: () => currentState,
    });

    await controller.initialize(host, async () => currentLife);
    currentLife = life("live2d-deadbeef");
    await controller.refresh();
    currentLife = life("default-png");
    currentState = "speaking";
    await controller.refresh();

    expect(controller.currentBodyId).toBe("default-png");
    expect(providers.map((provider) => provider.states)).toEqual([
      ["thinking"],
      ["thinking"],
      ["speaking"],
    ]);
    expect(renderers[1]?.disposeCalls).toBe(1);
    expect(host.querySelectorAll("[data-body-id]")).toHaveLength(1);
    expect(host.querySelector("[data-body-id]")?.getAttribute("data-body-id")).toBe(
      "default-png",
    );

    controller.dispose();
  });

  it("waits for async old renderer cleanup before reusing the host", async () => {
    const host = document.createElement("div");
    let currentLife = life("body-a");
    const oldRenderer = new AsyncDisposingRenderer();
    const newRenderer = new RecordingRenderer("body-b");
    const controller = new BodyRuntimeBindingController({
      loadRegistrySnapshot: async () => emptyRegistry(),
      installRegistrySnapshot: () => undefined,
      loadCurrentLife: async () => currentLife,
      createPresentation: (bodyId) => ({
        provider: new ImmediateProvider(),
        renderer: bodyId === "body-a" ? oldRenderer : newRenderer,
      }),
      getCurrentState: () => "idle",
    });

    await controller.initialize(host, async () => currentLife);
    currentLife = life("body-b");
    let refreshSettled = false;
    const refresh = controller.refresh().then(() => {
      refreshSettled = true;
    });

    await flushMicrotasks();
    expect(oldRenderer.disposeCalls).toBe(1);
    expect(refreshSettled).toBe(false);
    expect(host.querySelector("[data-body-id]")?.getAttribute("data-body-id")).toBe(
      "async-dispose",
    );

    oldRenderer.disposeGate.resolve();
    await refresh;
    expect(newRenderer.rendered).toEqual([
      { resourcePath: "idle.png", state: "idle" },
    ]);
    expect(host.querySelector("[data-body-id]")?.getAttribute("data-body-id")).toBe(
      "body-b",
    );
    controller.dispose();
  });

  it("fences rapid A to B to C rebinding and leaves one current host", async () => {
    const host = document.createElement("div");
    const firstMount = new Deferred<void>();
    const renderers = new Map<string, RecordingRenderer>();
    let currentLife = life("body-a");
    let currentState: BodyState = "idle";
    const controller = new BodyRuntimeBindingController({
      loadRegistrySnapshot: async () => emptyRegistry(),
      installRegistrySnapshot: () => undefined,
      loadCurrentLife: async () => currentLife,
      createPresentation: (bodyId) => {
        const renderer = new RecordingRenderer(
          bodyId,
          bodyId === "body-a" ? firstMount : undefined,
        );
        renderers.set(bodyId, renderer);
        return {
          provider: new ImmediateProvider(),
          renderer,
        };
      },
      getCurrentState: () => currentState,
    });

    const initial = controller.initialize(host, async () => currentLife);
    await flushMicrotasks();

    currentLife = life("body-b");
    const rebindingB = controller.refresh();
    currentLife = life("body-c");
    currentState = "speaking";
    const rebindingC = controller.refresh();

    firstMount.resolve();
    await Promise.all([initial, rebindingB, rebindingC]);
    await flushMicrotasks();

    expect(controller.currentBodyId).toBe("body-c");
    expect(renderers.get("body-a")?.disposeCalls).toBe(1);
    expect(renderers.has("body-b")).toBe(false);
    expect(renderers.get("body-c")?.rendered).toEqual([
      { resourcePath: "speaking.png", state: "speaking" },
    ]);
    expect(host.querySelectorAll("[data-body-id]")).toHaveLength(1);
    expect(host.querySelector("[data-body-id]")?.getAttribute("data-body-id")).toBe(
      "body-c",
    );

    controller.dispose();
  });

  it("does not recreate a renderer after disposal while a refresh is pending", async () => {
    const lifeRead = new Deferred<LifeIdentity>();
    let presentations = 0;
    const controller = new BodyRuntimeBindingController({
      loadRegistrySnapshot: async () => emptyRegistry(),
      installRegistrySnapshot: () => undefined,
      loadCurrentLife: () => lifeRead.promise,
      createPresentation: () => {
        presentations += 1;
        return {
          provider: new ImmediateProvider(),
          renderer: new RecordingRenderer("late"),
        };
      },
      getCurrentState: () => "idle",
    });
    controller.attachHost(document.createElement("div"));
    const refresh = controller.refresh();
    controller.dispose();
    lifeRead.resolve(life("late"));
    await refresh;

    expect(presentations).toBe(0);
    expect(controller.currentBodyId).toBeUndefined();
  });
});
