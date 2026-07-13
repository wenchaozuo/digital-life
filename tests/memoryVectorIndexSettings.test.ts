import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MemoryVectorIndexController,
  type ICurrentLifeService,
  type TimerScheduler,
} from "../src/settings/model/memoryVectorIndexController.ts";
import type {
  IMemoryVectorIndexService,
  MemoryVectorIndexStatus,
  VectorIndexJobResult,
} from "../src/settings/model/memoryVectorIndexService.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function status(overrides: Partial<MemoryVectorIndexStatus> = {}): MemoryVectorIndexStatus {
  return {
    lifeId: "life-from-authority",
    activeEmbeddingProfileExists: true,
    credentialExists: true,
    embeddingModel: "test-embedding",
    configuredDimension: 3,
    indexDirectoryExists: false,
    indexedCount: 0,
    eligibleMemoryCount: 2,
    rebuildRunning: false,
    lastJob: null,
    rebuildRecommended: true,
    reason: "The derived index directory does not exist.",
    ...overrides,
  };
}

function job(statusValue: VectorIndexJobResult["status"]): VectorIndexJobResult {
  return {
    jobId: "job-1",
    lifeId: "life-from-authority",
    status: statusValue,
    progress: {
      scannedCount: statusValue === "scanning" ? 4 : 0,
      eligibleCount: statusValue === "scanning" ? 3 : 0,
      embeddedCount: statusValue === "embedding" ? 2 : 0,
      indexedCount: statusValue === "completed" ? 2 : 0,
      skippedCandidateCount: 1,
      skippedSensitiveCount: 1,
      currentBatch: statusValue === "embedding" ? 1 : 0,
      totalBatches: statusValue === "embedding" ? 2 : 0,
      embeddingModel: "test-embedding",
      dimension: 3,
    },
    report: null,
    errorCode: statusValue === "cancelled" ? "REBUILD_CANCELLED" : null,
    errorMessage: statusValue === "cancelled" ? "The rebuild was cancelled." : null,
  };
}

class FakeTimerScheduler implements TimerScheduler {
  private nextHandle = 1;
  readonly callbacks = new Map<number, () => void>();
  set(callback: () => void): ReturnType<typeof setTimeout> {
    const handle = this.nextHandle;
    this.nextHandle += 1;
    this.callbacks.set(handle, callback);
    return handle as ReturnType<typeof setTimeout>;
  }
  clear(handle: ReturnType<typeof setTimeout>): void {
    this.callbacks.delete(handle as unknown as number);
  }
  runOne(): void {
    const next = this.callbacks.entries().next().value as [number, () => void] | undefined;
    if (!next) {
      return;
    }
    this.callbacks.delete(next[0]);
    next[1]();
  }
}

function createService(
  initialStatus: MemoryVectorIndexStatus,
  jobs: VectorIndexJobResult[] = [],
) {
  const calls = { status: 0, start: 0, getJob: 0, cancel: 0 };
  const service: IMemoryVectorIndexService = {
    async getStatus() {
      calls.status += 1;
      return initialStatus;
    },
    async startRebuild() {
      calls.start += 1;
      return "job-1";
    },
    async getJob() {
      calls.getJob += 1;
      return jobs.shift() ?? job("queued");
    },
    async cancelJob() {
      calls.cancel += 1;
      return job("embedding");
    },
  };
  return { calls, service };
}

const lifeService: ICurrentLifeService = {
  async getCurrentLife() {
    return { id: "life-from-authority" };
  },
};

async function flush(): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

test("index panel loads only status and never starts a rebuild automatically", async () => {
  const { calls, service } = createService(status());
  const controller = new MemoryVectorIndexController(service, lifeService, new FakeTimerScheduler());
  await controller.activate();
  assert.equal(calls.status, 1);
  assert.equal(calls.start, 0);
  assert.equal(controller.canStartRebuild, true);
});

test("missing active profile or credential disables rebuild", async () => {
  const noProfile = createService(status({ activeEmbeddingProfileExists: false }));
  const noCredential = createService(status({ credentialExists: false }));
  const first = new MemoryVectorIndexController(noProfile.service, lifeService, new FakeTimerScheduler());
  const second = new MemoryVectorIndexController(noCredential.service, lifeService, new FakeTimerScheduler());
  await Promise.all([first.activate(), second.activate()]);
  assert.equal(first.canStartRebuild, false);
  assert.equal(second.canStartRebuild, false);
});

test("rebuild waits for confirmation, then stores job id and begins one poll timer", async () => {
  const timers = new FakeTimerScheduler();
  const { calls, service } = createService(status(), [job("queued")]);
  const controller = new MemoryVectorIndexController(service, lifeService, timers);
  await controller.activate();
  assert.equal(await controller.confirmRebuild(), false);
  assert.equal(calls.start, 0);
  assert.equal(controller.requestRebuildConfirmation(), true);
  assert.equal(calls.start, 0);
  assert.equal(await controller.confirmRebuild(), true);
  assert.equal(calls.start, 1);
  assert.equal(controller.job?.jobId, "job-1");
  assert.equal(timers.callbacks.size, 1);
  controller.requestRebuildConfirmation();
  assert.equal(timers.callbacks.size, 1);
});

test("polling uses backend terminal state, stops once completed, and refreshes status", async () => {
  const timers = new FakeTimerScheduler();
  const { calls, service } = createService(status(), [job("completed")]);
  const controller = new MemoryVectorIndexController(service, lifeService, timers);
  await controller.activate();
  controller.requestRebuildConfirmation();
  await controller.confirmRebuild();
  timers.runOne();
  await flush();
  assert.equal(calls.getJob, 1);
  assert.equal(controller.job?.status, "completed");
  assert.equal(timers.callbacks.size, 0);
  assert.ok(calls.status >= 2);
});

test("cancellation submits once and waits for backend confirmation before marking cancelled", async () => {
  const timers = new FakeTimerScheduler();
  const { calls, service } = createService(status(), [job("cancelled")]);
  const controller = new MemoryVectorIndexController(service, lifeService, timers);
  await controller.activate();
  controller.requestRebuildConfirmation();
  await controller.confirmRebuild();
  assert.equal(await controller.requestCancel(), true);
  assert.equal(calls.cancel, 1);
  assert.equal(controller.job?.status, "embedding");
  assert.equal(controller.canCancelJob, false);
  timers.runOne();
  await flush();
  assert.equal(controller.job?.status, "cancelled");
  assert.equal(timers.callbacks.size, 0);
});

test("deactivation clears an active poll timer and reactivation restores backend task state", async () => {
  const timers = new FakeTimerScheduler();
  const running = job("scanning");
  const { calls, service } = createService(status({ rebuildRunning: true, lastJob: running }));
  const controller = new MemoryVectorIndexController(service, lifeService, timers);
  await controller.activate();
  assert.equal(timers.callbacks.size, 1);
  controller.deactivate();
  assert.equal(timers.callbacks.size, 0);
  await controller.activate();
  assert.equal(calls.status, 2);
  assert.equal(timers.callbacks.size, 1);
});

test("service DTOs and panel never expose request secrets, paths, memory text, or vectors", () => {
  const serviceSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/memoryVectorIndexService.ts"),
    "utf8",
  );
  const panelSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/MemoryVectorIndexPanel.vue"),
    "utf8",
  );
  assert.doesNotMatch(serviceSource, /apiKey|baseUrl|lanceDbPath|vectorSpace|memoryContent/i);
  assert.doesNotMatch(panelSource, /job\.summary|apiKey|baseUrl|credential manager|currentDirectory/i);
});

test("embedding changes refresh status only and cannot auto-start a rebuild", () => {
  const viewSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/ModelProfilesView.vue"),
    "utf8",
  );
  assert.match(viewSource, /function refreshMemoryVectorIndexStatus/);
  assert.match(viewSource, /if \(props\.purpose === "embedding"\)/);
  assert.doesNotMatch(viewSource, /start_memory_vector_index_rebuild/);
});

test("panel stops polling on visibility and unmount while showing safe phase guidance", () => {
  const panelSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/MemoryVectorIndexPanel.vue"),
    "utf8",
  );
  assert.match(panelSource, /document\.visibilityState === "hidden"/);
  assert.match(panelSource, /controller\.deactivate\(\)/);
  assert.match(panelSource, /onUnmounted/);
  assert.match(panelSource, /Active Embedding model changed/);
  assert.match(panelSource, /window\.confirm/);
  assert.doesNotMatch(panelSource, /%|progressbar/i);
});

test("settings capability has life and index commands while chat and main do not", () => {
  const settings = fs.readFileSync(
    path.join(__dirname, "../src-tauri/permissions/settings-commands.toml"),
    "utf8",
  );
  const chat = fs.readFileSync(
    path.join(__dirname, "../src-tauri/permissions/chat-commands.toml"),
    "utf8",
  );
  const main = fs.readFileSync(
    path.join(__dirname, "../src-tauri/permissions/main-commands.toml"),
    "utf8",
  );
  assert.match(settings, /get_current_life_identity/);
  assert.match(settings, /get_memory_vector_index_status/);
  assert.doesNotMatch(chat, /memory_vector_index/);
  assert.doesNotMatch(main, /memory_vector_index/);
});
