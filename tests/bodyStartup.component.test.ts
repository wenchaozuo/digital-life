import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { BodyRenderer } from "../src/body/bodyRenderer";
import type { BodyProvider, BodySnapshot, BodyState } from "../src/body/types";
import type { LifeIdentity } from "../src/life/lifeIdentity";
import type { PersonaTemplate } from "../src/persona/personaTemplate";

class Deferred<T> {
  readonly promise: Promise<T>;
  resolve!: (value: T | PromiseLike<T>) => void;
  reject!: (reason?: unknown) => void;

  constructor() {
    this.promise = new Promise<T>((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
  }
}

class ControlledBodyProvider implements BodyProvider {
  readonly pending = new Map<BodyState, Deferred<BodySnapshot>>();
  readonly switchCalls: BodyState[] = [];
  private current: BodySnapshot = {
    resourcePath: "controlled-current.png",
    state: "idle",
  };

  async load(state: BodyState): Promise<BodySnapshot> {
    return this.switchState(state);
  }

  switchState(state: BodyState): Promise<BodySnapshot> {
    this.switchCalls.push(state);
    const deferred = new Deferred<BodySnapshot>();
    this.pending.set(state, deferred);
    return deferred.promise.then((snapshot) => {
      this.current = snapshot;
      return snapshot;
    });
  }

  getCurrent(): BodySnapshot {
    return this.current;
  }
}

class RecordingBodyRenderer implements BodyRenderer {
  readonly mountedHosts: HTMLElement[] = [];
  readonly renderedSnapshots: BodySnapshot[] = [];
  disposeCalls = 0;

  mount(host: HTMLElement): void {
    this.mountedHosts.push(host);
  }

  render(snapshot: BodySnapshot): void {
    this.renderedSnapshots.push(snapshot);
  }

  dispose(): void {
    this.disposeCalls += 1;
  }
}

function makeLife(bodyId: string): LifeIdentity {
  return {
    id: "life-1",
    name: "Test Life",
    createdAt: "2026-08-28T00:00:00.000Z",
    version: 3,
    bodyId,
    personaId: "persona-1",
    personaVersion: 2,
  };
}

function makePersona(): PersonaTemplate {
  return {
    id: "persona-1",
    name: "Test Persona",
    version: 2,
    coreValues: [],
    personalityTraits: [],
    communicationStyle: {
      tone: "direct",
      preferredExpressions: [],
      avoidedExpressions: [],
    },
    background: "",
    interests: [],
    initiativeLevel: "balanced",
    boundaries: [],
  };
}

async function flushMicrotasks(rounds = 20): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("main current-Life body startup", () => {
  it("retains a pre-binding expression, uses Life.bodyId, pairs the composition, and fences the initial race", async () => {
    vi.resetModules();
    const body = await import("../src/body");
    const lifeModule = await import("../src/life");
    const personaModule = await import("../src/persona");
    const storageModule = await import("../src/storage");

    const events: string[] = [];
    const storageInit = new Deferred<void>();
    const lifeInit = new Deferred<LifeIdentity>();
    const listenerRegistration = new Deferred<() => void>();
    const unlisten = vi.fn();
    let listenerHandler: ((event: {
      version: 1;
      state: BodyState;
      source: "conversation";
    }) => void) | undefined;
    const provider = new ControlledBodyProvider();
    const renderer = new RecordingBodyRenderer();
    const composition = { provider, renderer };
    const life = makeLife("restored-unknown-body");

    const installRegistry = body.installManagedBodyPackageRegistrySnapshot;
    vi.spyOn(body.bodyPackageService, "getRegistrySnapshot").mockImplementation(async () => {
      events.push("registry");
      return [];
    });
    vi.spyOn(body, "installManagedBodyPackageRegistrySnapshot").mockImplementation(
      (snapshot) => {
        events.push("registry-install");
        installRegistry(snapshot);
      },
    );

    vi.spyOn(body.bodyExpressionBridge, "listenForBodyExpression").mockImplementation(
      async (handler) => {
        events.push("listener");
        listenerHandler = handler;
        return listenerRegistration.promise;
      },
    );
    vi.spyOn(storageModule.storageService, "initialize").mockImplementation(async () => {
      events.push("storage");
      await storageInit.promise;
    });
    vi.spyOn(lifeModule, "initializeDefaultLife").mockImplementation(async () => {
      events.push("life");
      return lifeInit.promise;
    });
    const updateLifeSpy = vi.spyOn(storageModule.storageService, "updateLifeBaseInfo");
    const saveLifeSpy = vi.spyOn(storageModule.storageService, "saveLife");
    const factorySpy = vi
      .spyOn(body, "createBodyPresentationForBodyId")
      .mockImplementation((bodyId) => {
        events.push(`factory:${bodyId}`);
        return composition;
      });
    vi.spyOn(personaModule.personaManager, "getById").mockImplementation(async (id) => {
      events.push(`persona:${id}`);
      return makePersona();
    });

    const { default: App } = await import("../src/App.vue");
    const wrapper = mount(App);
    try {
      expect(events.slice(0, 2)).toEqual(["listener", "storage"]);
      listenerRegistration.resolve(unlisten);
      await flushMicrotasks();

      listenerHandler?.({ version: 1, state: "thinking", source: "conversation" });
      expect(body.bodyStateMachine.getState()).toBe("thinking");
      expect(provider.switchCalls).toEqual([]);

      storageInit.resolve();
      await flushMicrotasks();
      expect(lifeModule.initializeDefaultLife).toHaveBeenCalledTimes(1);

      lifeInit.resolve(life);
      await flushMicrotasks();
      expect(factorySpy).toHaveBeenCalledWith(life.bodyId);
      expect(events.indexOf("listener")).toBeLessThan(events.indexOf("storage"));
      expect(events.indexOf("storage")).toBeLessThan(events.indexOf("life"));
      expect(events.indexOf("registry")).toBeGreaterThan(events.indexOf("storage"));
      expect(events.indexOf("registry")).toBeLessThan(events.indexOf("registry-install"));
      expect(events.indexOf("registry-install")).toBeLessThan(events.indexOf("life"));
      expect(events.indexOf("life")).toBeLessThan(events.indexOf(`factory:${life.bodyId}`));
      expect(renderer.mountedHosts).toEqual([
        wrapper.find(".body-renderer-host").element,
      ]);
      expect(provider.switchCalls).toEqual(["thinking"]);

      // A newer expression during the initial Life-bound render owns the
      // frozen coordinator generation and is the only visible result.
      body.bodyStateMachine.transition("waiting");
      await flushMicrotasks();
      expect(provider.switchCalls).toEqual(["thinking", "waiting"]);

      provider.pending.get("waiting")?.resolve({
        resourcePath: "waiting.png",
        state: "waiting",
      });
      await flushMicrotasks();
      provider.pending.get("thinking")?.resolve({
        resourcePath: "thinking.png",
        state: "thinking",
      });
      await flushMicrotasks();

      expect(renderer.renderedSnapshots).toEqual([
        { resourcePath: "waiting.png", state: "waiting" },
      ]);
      expect(renderer.disposeCalls).toBe(0);

      body.bodyStateMachine.transition("speaking");
      await flushMicrotasks();
      expect(provider.switchCalls).toEqual(["thinking", "waiting", "speaking"]);

      provider.pending.get("speaking")?.resolve({
        resourcePath: "speaking.png",
        state: "speaking",
      });
      await flushMicrotasks();

      expect(renderer.renderedSnapshots).toEqual([
        { resourcePath: "waiting.png", state: "waiting" },
        { resourcePath: "speaking.png", state: "speaking" },
      ]);
      expect(renderer.disposeCalls).toBe(0);
      expect(wrapper.text()).toContain("State: speaking");
      expect(events.indexOf("persona:persona-1")).toBeGreaterThan(
        events.indexOf("factory:restored-unknown-body"),
      );
      expect(updateLifeSpy).not.toHaveBeenCalled();
      expect(saveLifeSpy).not.toHaveBeenCalled();
    } finally {
      wrapper.unmount();
      await flushMicrotasks();
    }

    expect(unlisten).toHaveBeenCalledTimes(1);
    expect(renderer.disposeCalls).toBe(1);
  });

  it("discards late Life initialization after unmount without creating a runtime or restarting the listener", async () => {
    vi.resetModules();
    const body = await import("../src/body");
    const lifeModule = await import("../src/life");
    const storageModule = await import("../src/storage");

    const storageInit = new Deferred<void>();
    const listenerRegistration = new Deferred<() => void>();
    const unlisten = vi.fn();
    const life = makeLife("default-png");
    let listenerHandler: ((event: {
      version: 1;
      state: BodyState;
      source: "conversation";
    }) => void) | undefined;

    vi.spyOn(body.bodyExpressionBridge, "listenForBodyExpression").mockImplementation(
      async (handler) => {
        listenerHandler = handler;
        return listenerRegistration.promise;
      },
    );
    vi.spyOn(storageModule.storageService, "initialize").mockImplementation(async () => {
      await storageInit.promise;
    });
    const lifeSpy = vi
      .spyOn(lifeModule, "initializeDefaultLife")
      .mockImplementation(async () => life);
    const factorySpy = vi.spyOn(body, "createBodyPresentationForBodyId");

    const { default: App } = await import("../src/App.vue");
    const wrapper = mount(App);
    wrapper.unmount();

    listenerRegistration.resolve(unlisten);
    storageInit.resolve();
    await flushMicrotasks();

    expect(unlisten).toHaveBeenCalledTimes(1);
    expect(lifeSpy).not.toHaveBeenCalled();
    expect(factorySpy).not.toHaveBeenCalled();
    expect(body.bodyStateMachine.getState()).toBe("idle");

    // A stale handler reference cannot create a presentation after the
    // subscription and lifecycle have both been retired.
    listenerHandler?.({ version: 1, state: "thinking", source: "conversation" });
    await flushMicrotasks();
    expect(factorySpy).not.toHaveBeenCalled();
  });

  it("discards a provider completion after unmount without calling renderer.render", async () => {
    vi.resetModules();
    const body = await import("../src/body");
    const lifeModule = await import("../src/life");
    const personaModule = await import("../src/persona");
    const storageModule = await import("../src/storage");

    const provider = new ControlledBodyProvider();
    const renderer = new RecordingBodyRenderer();
    const life = makeLife("default-png");
    const unlisten = vi.fn();

    vi.spyOn(body.bodyExpressionBridge, "listenForBodyExpression").mockResolvedValue(
      unlisten,
    );
    vi.spyOn(storageModule.storageService, "initialize").mockResolvedValue();
    vi.spyOn(lifeModule, "initializeDefaultLife").mockResolvedValue(life);
    vi.spyOn(personaModule.personaManager, "getById").mockResolvedValue(makePersona());
    vi.spyOn(body, "createBodyPresentationForBodyId").mockReturnValue({
      provider,
      renderer,
    });

    const { default: App } = await import("../src/App.vue");
    const wrapper = mount(App);
    try {
      await flushMicrotasks();
      provider.pending.get("idle")?.resolve({
        resourcePath: "idle.png",
        state: "idle",
      });
      await flushMicrotasks();
      expect(renderer.renderedSnapshots).toEqual([
        { resourcePath: "idle.png", state: "idle" },
      ]);

      body.bodyStateMachine.transition("thinking");
      await flushMicrotasks();
      expect(provider.pending.has("thinking")).toBe(true);

      wrapper.unmount();
      provider.pending.get("thinking")?.resolve({
        resourcePath: "thinking.png",
        state: "thinking",
      });
      await flushMicrotasks();

      expect(renderer.renderedSnapshots).toEqual([
        { resourcePath: "idle.png", state: "idle" },
      ]);
    } finally {
      wrapper.unmount();
      await flushMicrotasks();
    }
  });
});
