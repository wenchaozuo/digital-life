import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

import { BodyRenderCoordinator } from "../src/body/bodyRenderCoordinator.ts";
import { BodyExpressionListenerLifecycle } from "../src/body/expressionBridge.ts";
import { FallbackBodyProvider } from "../src/body/fallbackBodyProvider.ts";
import type { BodyProvider, BodySnapshot, BodyState } from "../src/body/types.ts";

class FakeBodyProvider implements BodyProvider {
  readonly reloadCalls: BodyState[] = [];
  readonly switchCalls: BodyState[] = [];
  private readonly outcome: "resolve" | "reject";
  private readonly resourcePrefix: string;
  private current: BodySnapshot;

  constructor(outcome: "resolve" | "reject", resourcePrefix: string) {
    this.outcome = outcome;
    this.resourcePrefix = resourcePrefix;
    this.current = { resourcePath: `${resourcePrefix}-current`, state: "idle" };
  }

  async load(state: BodyState): Promise<BodySnapshot> {
    this.reloadCalls.push(state);
    return this.settle(state);
  }

  async switchState(state: BodyState): Promise<BodySnapshot> {
    this.switchCalls.push(state);
    return this.settle(state);
  }

  getCurrent(): BodySnapshot {
    return this.current;
  }

  private async settle(state: BodyState): Promise<BodySnapshot> {
    if (this.outcome === "reject") {
      throw new Error(`${this.resourcePrefix} failed`);
    }
    const snapshot = { resourcePath: `${this.resourcePrefix}-${state}`, state };
    this.current = snapshot;
    return snapshot;
  }
}

test("fallback: primary success avoids the fallback entirely", async () => {
  const primary = new FakeBodyProvider("resolve", "primary");
  const fallback = new FakeBodyProvider("resolve", "fallback");
  const provider = new FallbackBodyProvider(primary, fallback);

  const loaded = await provider.load("thinking");
  assert.deepEqual(loaded, { resourcePath: "primary-thinking", state: "thinking" });
  assert.equal(fallback.reloadCalls.length, 0);
  assert.equal(fallback.switchCalls.length, 0);

  provider.getCurrent();
  const switched = await provider.switchState("waiting");
  assert.deepEqual(switched, { resourcePath: "primary-waiting", state: "waiting" });
  assert.equal(fallback.switchCalls.length, 0);
});

test("fallback: primary failure activates the fallback once per operation", async () => {
  const primary = new FakeBodyProvider("reject", "primary");
  const fallback = new FakeBodyProvider("resolve", "fallback");
  const provider = new FallbackBodyProvider(primary, fallback);

  const loaded = await provider.load("thinking");
  assert.deepEqual(loaded, { resourcePath: "fallback-thinking", state: "thinking" });
  assert.equal(fallback.reloadCalls.length, 1, "no double retry");
  assert.equal(primary.reloadCalls.length, 1);

  const switched = await provider.switchState("error");
  assert.deepEqual(switched, { resourcePath: "fallback-error", state: "error" });
  assert.equal(fallback.switchCalls.length, 1, "no double retry");
  assert.deepEqual(fallback.switchCalls, ["error"], "requested state is preserved");
});

test("fallback: primary failure never propagates after fallback success", async () => {
  const primary = new FakeBodyProvider("reject", "primary");
  const fallback = new FakeBodyProvider("resolve", "fallback");
  const provider = new FallbackBodyProvider(primary, fallback);

  const snapshot = await provider.switchState("thinking");
  assert.equal(snapshot.state, "thinking");
  assert.equal(snapshot.resourcePath, "fallback-thinking");
});

test("fallback: double failure surfaces one bounded rejection", async () => {
  const primary = new FakeBodyProvider("reject", "primary");
  const fallback = new FakeBodyProvider("reject", "fallback");
  const provider = new FallbackBodyProvider(primary, fallback);

  await assert.rejects(provider.switchState("thinking"), /fallback failed/);
});

test("fallback: getCurrent follows the last successful provider", async () => {
  const primary = new FakeBodyProvider("resolve", "primary");
  const fallback = new FakeBodyProvider("resolve", "fallback");
  const provider = new FallbackBodyProvider(primary, fallback);

  // Before any successful operation the stable fallback current is shown.
  assert.deepEqual(provider.getCurrent(), { resourcePath: "fallback-current", state: "idle" });

  await provider.switchState("thinking");
  assert.deepEqual(provider.getCurrent(), { resourcePath: "primary-thinking", state: "thinking" });

  const failing = new FakeBodyProvider("reject", "primary");
  const fallbackAgain = new FakeBodyProvider("resolve", "fallback");
  const fallbackProvider = new FallbackBodyProvider(failing, fallbackAgain);
  await fallbackProvider.switchState("error");
  assert.deepEqual(fallbackProvider.getCurrent(), {
    resourcePath: "fallback-error",
    state: "error",
  });
});

class Deferred {
  resolve!: (snapshot: BodySnapshot) => void;
  readonly promise: Promise<BodySnapshot>;

  constructor() {
    this.promise = new Promise<BodySnapshot>((resolve) => {
      this.resolve = resolve;
    });
  }
}

class ControlledBodyProvider implements BodyProvider {
  readonly pending = new Map<BodyState, Deferred>();
  readonly switchCalls: BodyState[] = [];

  async switchState(state: BodyState): Promise<BodySnapshot> {
    this.switchCalls.push(state);
    const deferred = new Deferred();
    this.pending.set(state, deferred);
    return deferred.promise;
  }

  async load(state: BodyState): Promise<BodySnapshot> {
    return this.switchState(state);
  }

  getCurrent(): BodySnapshot {
    return { resourcePath: "controlled-current", state: "idle" };
  }
}

test("render coordinator fences stale provider completions", async () => {
  const provider = new ControlledBodyProvider();
  const coordinator = new BodyRenderCoordinator(provider);

  const thinking = coordinator.render("thinking");
  const idle = coordinator.render("idle");

  // The idle render resolves first and owns the current generation.
  provider.pending.get("idle")?.resolve({ resourcePath: "idle.png", state: "idle" });
  const idleResult = await idle;
  assert.equal(idleResult.applied, true);
  assert.deepEqual(idleResult.snapshot, { resourcePath: "idle.png", state: "idle" });

  // The late thinking completion is ignored and never applied.
  provider.pending.get("thinking")?.resolve({ resourcePath: "thinking.png", state: "thinking" });
  const thinkingResult = await thinking;
  assert.equal(thinkingResult.applied, false);

  assert.deepEqual(coordinator.getCurrent(), { resourcePath: "idle.png", state: "idle" });
  assert.equal(provider.switchCalls.length, 2);
});

test("render coordinator applies the initial render when no newer render races it", async () => {
  const provider = new ControlledBodyProvider();
  const coordinator = new BodyRenderCoordinator(provider);

  const initial = coordinator.render("idle");
  provider.pending.get("idle")?.resolve({ resourcePath: "idle.png", state: "idle" });
  const result = await initial;

  assert.equal(result.applied, true);
  assert.deepEqual(coordinator.getCurrent(), { resourcePath: "idle.png", state: "idle" });
});

test("listener lifecycle unlistens exactly once when registration resolves after stop", async () => {
  let resolveRegistration: ((unlisten: () => void) => void) | undefined;
  const registration = new Promise<() => void>((resolve) => {
    resolveRegistration = resolve;
  });
  let unlistenCalls = 0;
  const lifecycle = new BodyExpressionListenerLifecycle(() => registration);

  lifecycle.start(() => {});
  lifecycle.stop(); // unmount happens while registration is still pending

  resolveRegistration?.(() => {
    unlistenCalls += 1;
  });
  await flushMicrotasks();

  assert.equal(unlistenCalls, 1, "the late-resolved unlisten is invoked exactly once");
});

test("listener lifecycle unlistens exactly once in the normal path", async () => {
  let unlistenCalls = 0;
  const lifecycle = new BodyExpressionListenerLifecycle(async () => {
    return () => {
      unlistenCalls += 1;
    };
  });

  lifecycle.start(() => {});
  await flushMicrotasks();
  lifecycle.stop();
  lifecycle.stop(); // a second stop must not double-unlisten

  assert.equal(unlistenCalls, 1);
});

test("main expression-listener registration starts before the long initialization", () => {
  const appSource = fs.readFileSync(new URL("../src/App.vue", import.meta.url), "utf8");
  const listenerStart = appSource.indexOf("bodyExpressionListener.start");
  const storageInit = appSource.indexOf("await storageService.initialize()");
  const lifeInit = appSource.indexOf("await initializeDefaultLife()");
  const personaLoad = appSource.indexOf("personaManager.getById");

  assert.ok(listenerStart >= 0, "App.vue must start the listener controller");
  assert.ok(storageInit >= 0 && lifeInit >= 0 && personaLoad >= 0);
  assert.ok(listenerStart < storageInit, "listener registration precedes storage initialization");
  assert.ok(listenerStart < lifeInit, "listener registration precedes Life initialization");
  assert.ok(listenerStart < personaLoad, "listener registration precedes persona loading");
});

async function flushMicrotasks(rounds = 16): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}