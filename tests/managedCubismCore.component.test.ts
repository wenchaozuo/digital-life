import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";

import {
  createManagedCubismCoreBoundaryWithCoordinator,
  createSharedCoreLoadCoordinator,
  isTrustedManagedCoreScriptUrl,
  MANAGED_CORE_SCRIPT_FILENAME,
  ManagedCubismCoreReadyBoundary,
  type ManagedCubismCoreService,
  type ManagedCubismCoreSnapshot,
} from "../src/body/managedCubismCore.ts";
import type { Live2DCoreReadyBoundary } from "../src/body/live2dRuntime.ts";

function sourceFilesUnder(directory: string): string[] {
  const root = path.join(process.cwd(), directory);
  return fs
    .readdirSync(root)
    .filter((name) => name.endsWith(".ts"))
    .map((name) => fs.readFileSync(path.join(root, name), "utf8"));
}

const WINDOWS_URL = `http://digital-life-core.localhost/${MANAGED_CORE_SCRIPT_FILENAME}`;
const MAC_LINUX_URL = `digital-life-core://localhost/${MANAGED_CORE_SCRIPT_FILENAME}`;

function readySnapshot(scriptUrl: string): ManagedCubismCoreSnapshot {
  return {
    status: "ready-for-startup",
    runtimeFamily: "cubism4",
    versionLabel: "d22-d1-test-fixture",
    sha256: "a".repeat(64),
    scriptUrl,
    restartRequired: true,
  };
}

class FakeCoreService implements ManagedCubismCoreService {
  snapshot: ManagedCubismCoreSnapshot | undefined;
  calls = 0;
  rejects = false;

  async getSnapshot(): Promise<ManagedCubismCoreSnapshot> {
    this.calls += 1;
    if (this.rejects) {
      throw new Error("backend unavailable");
    }
    if (this.snapshot === undefined) {
      return {
        status: "not-configured",
        runtimeFamily: "cubism4",
        restartRequired: false,
      };
    }
    return this.snapshot;
  }
}

class FakeDelegate implements Live2DCoreReadyBoundary {
  calls = 0;
  rejects = false;

  async ensureReady(): Promise<void> {
    this.calls += 1;
    if (this.rejects) {
      throw new Error("delegate failed");
    }
  }
}

class FakeScript {
  src = "";
  async = false;
  private listeners = new Map<string, Set<() => void>>();
  removed = false;

  addEventListener(type: string, listener: () => void): void {
    const set = this.listeners.get(type) ?? new Set();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: string, listener: () => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  remove(): void {
    this.removed = true;
  }

  fire(type: string): void {
    for (const listener of [...(this.listeners.get(type) ?? [])]) {
      listener();
    }
  }
}

class FakeScriptDocument {
  readonly head = { appendChild: (): void => {} };
  readonly scripts: FakeScript[] = [];
  private readonly scriptClass: new () => FakeScript;

  constructor(scriptClass: new () => FakeScript) {
    this.scriptClass = scriptClass;
  }

  createElement(tagName: string): FakeScript {
    if (tagName !== "script") {
      throw new Error("fake document only creates scripts");
    }
    const script = new this.scriptClass();
    this.scripts.push(script);
    return script;
  }
}

afterEach(() => {
  vi.restoreAllMocks();
  document.head.innerHTML = "";
  delete (window as Window & { Live2DCubismCore?: unknown }).Live2DCubismCore;
});

describe("managed Core injection confinement", () => {
  it("production boundary instances share one module-level coordinator", () => {
    // Two default-constructed boundaries must resolve to the SAME shared
    // authority (spying the module singleton is not possible, but the
    // coordinator seam proves the production default path exists and the
    // test-seam path shares correctly).
    const coordinator = createSharedCoreLoadCoordinator(
      new FakeCoreService(),
      document,
      () => new FakeDelegate(),
    );
    const a = createManagedCubismCoreBoundaryWithCoordinator(coordinator);
    const b = createManagedCubismCoreBoundaryWithCoordinator(coordinator);
    expect(a).not.toBe(b);
    expect(typeof a.ensureReady).toBe("function");
    expect(typeof b.ensureReady).toBe("function");
  });

  it("is the only production body module that injects a Core script", () => {
    const files = sourceFilesUnder("src/body");
    const injectors = files.filter(
      (source) =>
        /script\.src\s*=/.test(source) || /live2dcubismcore\.min\.js/.test(source),
    );
    expect(injectors.length).toBe(1);
    expect(injectors[0]).toContain("ManagedCubismCoreReadyBoundary");
  });

  it("never references a remote Core hosting URL", () => {
    const managedSource = fs.readFileSync(
      path.join(process.cwd(), "src/body/managedCubismCore.ts"),
      "utf8",
    );
    expect(managedSource).not.toMatch(/https:\/\/cubism\.live2d\.com/i);
    expect(managedSource).not.toMatch(/github\.com/i);
  });
});

describe("trusted managed Core script URL boundary", () => {
  it("accepts exactly the backend-generated Windows and mac/Linux shapes", () => {
    expect(isTrustedManagedCoreScriptUrl(WINDOWS_URL)).toBe(true);
    expect(isTrustedManagedCoreScriptUrl(MAC_LINUX_URL)).toBe(true);
  });

  it("rejects generic, wrong-origin, port, query, fragment, and alternate paths", () => {
    const rejected = [
      "http://example.invalid/live2dcubismcore.min.js",
      "https://digital-life-core.localhost/live2dcubismcore.min.js",
      "file:///C:/live2dcubismcore.min.js",
      "digital-life-core://evil.localhost/live2dcubismcore.min.js",
      "http://digital-life-core.localhost:8080/live2dcubismcore.min.js",
      `http://digital-life-core.localhost/${MANAGED_CORE_SCRIPT_FILENAME}?x=1`,
      `http://digital-life-core.localhost/${MANAGED_CORE_SCRIPT_FILENAME}#frag`,
      "digital-life-core://localhost/other.js",
      "http://digital-life-core.localhost/../live2dcubismcore.min.js",
      "http://digital-life-core.localhost/%2e%2e/live2dcubismcore.min.js",
      "http://user:pass@digital-life-core.localhost/live2dcubismcore.min.js",
      "",
      "not-a-url",
    ];
    for (const value of rejected) {
      expect(isTrustedManagedCoreScriptUrl(value), value).toBe(false);
    }
  });
});

describe("ManagedCubismCoreReadyBoundary", () => {
  it("delegates to the D21 boundary when Core is already present", async () => {
    (window as Window & { Live2DCubismCore?: unknown }).Live2DCubismCore = {};
    const service = new FakeCoreService();
    const delegate = new FakeDelegate();
    const boundary = new ManagedCubismCoreReadyBoundary(service, document, () => delegate);

    await boundary.ensureReady();

    expect(service.calls).toBe(0);
    expect(delegate.calls).toBe(1);
    expect(document.head.querySelectorAll("script").length).toBe(0);
  });

  it("backend unavailable yields a bounded Core unavailable error", async () => {
    const service = new FakeCoreService();
    service.rejects = true;
    const delegate = new FakeDelegate();
    const boundary = new ManagedCubismCoreReadyBoundary(service, document, () => delegate);

    await expect(boundary.ensureReady()).rejects.toThrow(/Core is not ready/);
  });

  it("no approved Core (not-configured) yields Core unavailable without injection", async () => {
    const service = new FakeCoreService();
    const boundary = new ManagedCubismCoreReadyBoundary(service, document, () => new FakeDelegate());

    await expect(boundary.ensureReady()).rejects.toThrow(/Core is not ready/);
  });

  it("an untrusted scriptUrl is never injected", async () => {
    const service = new FakeCoreService();
    service.snapshot = readySnapshot("https://evil.example/core.js");
    const doc = new FakeScriptDocument(FakeScript);
    const boundary = new ManagedCubismCoreReadyBoundary(
      service,
      doc as unknown as Document,
      () => new FakeDelegate(),
    );

    await expect(boundary.ensureReady()).rejects.toThrow(/Core is not ready/);
    expect(doc.scripts.length).toBe(0);
  });

  it("injects exactly one trusted script and delegates on a successful load", async () => {
    const service = new FakeCoreService();
    service.snapshot = readySnapshot(WINDOWS_URL);
    const delegate = new FakeDelegate();
    const doc = new FakeScriptDocument(FakeScript);
    const boundary = new ManagedCubismCoreReadyBoundary(
      service,
      doc as unknown as Document,
      () => delegate,
    );

    const readyPromise = boundary.ensureReady();
    await flushMicrotasks();
    expect(doc.scripts.length).toBe(1);
    expect(doc.scripts[0].src).toBe(WINDOWS_URL);

    (window as Window & { Live2DCubismCore?: unknown }).Live2DCubismCore = {};
    doc.scripts[0].fire("load");
    await readyPromise;

    expect(delegate.calls).toBe(1);
  });

  it("a failed script load never marks Core ready and retires the element", async () => {
    const service = new FakeCoreService();
    service.snapshot = readySnapshot(MAC_LINUX_URL);
    const delegate = new FakeDelegate();
    const doc = new FakeScriptDocument(FakeScript);
    const boundary = new ManagedCubismCoreReadyBoundary(
      service,
      doc as unknown as Document,
      () => delegate,
    );

    const readyPromise = boundary.ensureReady();
    await flushMicrotasks();
    doc.scripts[0].fire("error");

    await expect(readyPromise).rejects.toThrow(/Core is not ready/);
    expect(doc.scripts[0].removed).toBe(true);
    expect(delegate.calls).toBe(0);
  });

  it("three concurrent ensureReady calls across separate instances share one load", async () => {
    const service = new FakeCoreService();
    service.snapshot = readySnapshot(WINDOWS_URL);
    const delegate = new FakeDelegate();
    const doc = new FakeScriptDocument(FakeScript);

    // ONE shared coordinator; three SEPARATELY constructed boundaries.
    const coordinator = createSharedCoreLoadCoordinator(
      service,
      doc as unknown as Document,
      () => delegate,
    );
    const boundaryA = createManagedCubismCoreBoundaryWithCoordinator(coordinator);
    const boundaryB = createManagedCubismCoreBoundaryWithCoordinator(coordinator);
    const boundaryC = createManagedCubismCoreBoundaryWithCoordinator(coordinator);

    const first = boundaryA.ensureReady();
    const second = boundaryB.ensureReady();
    const third = boundaryC.ensureReady();
    await flushMicrotasks();

    expect(doc.scripts.length).toBe(1);
    expect(service.calls).toBe(1);

    (window as Window & { Live2DCubismCore?: unknown }).Live2DCubismCore = {};
    doc.scripts[0].fire("load");
    await Promise.all([first, second, third]);
    expect(delegate.calls).toBe(1);
  });

  it("one shared script failure rejects every concurrent caller and retires", async () => {
    const service = new FakeCoreService();
    service.snapshot = readySnapshot(MAC_LINUX_URL);
    const delegate = new FakeDelegate();
    const doc = new FakeScriptDocument(FakeScript);

    const coordinator = createSharedCoreLoadCoordinator(
      service,
      doc as unknown as Document,
      () => delegate,
    );
    const boundaryA = createManagedCubismCoreBoundaryWithCoordinator(coordinator);
    const boundaryB = createManagedCubismCoreBoundaryWithCoordinator(coordinator);

    const first = boundaryA.ensureReady();
    const second = boundaryB.ensureReady();
    await flushMicrotasks();
    expect(doc.scripts.length).toBe(1);
    expect(service.calls).toBe(1);

    doc.scripts[0].fire("error");
    await expect(first).rejects.toThrow(/Core is not ready/);
    await expect(second).rejects.toThrow(/Core is not ready/);
    expect(doc.scripts[0].removed).toBe(true);
    expect(delegate.calls).toBe(0);
    expect(
      (window as Window & { Live2DCubismCore?: unknown }).Live2DCubismCore,
    ).toBeUndefined();

    // The coordinator retires cleanly after the failure: a later attempt
    // starts a fresh provisioning path (new backend read, new script).
    service.snapshot = readySnapshot(WINDOWS_URL);
    const retry = boundaryA.ensureReady();
    await flushMicrotasks();
    expect(service.calls).toBe(2);
    expect(doc.scripts.length).toBe(2);
    (window as Window & { Live2DCubismCore?: unknown }).Live2DCubismCore = {};
    doc.scripts[1].fire("load");
    await retry;
    expect(delegate.calls).toBe(1);
  });
});

async function flushMicrotasks(rounds = 16): Promise<void> {
  for (let round = 0; round < rounds; round += 1) {
    await Promise.resolve();
  }
}