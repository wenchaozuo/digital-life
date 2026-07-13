import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MemoryVectorSyncController,
  type ICurrentLifeService,
  type TimerScheduler,
} from "../src/settings/model/memoryVectorSyncController.ts";
import type {
  IMemoryVectorSyncService,
  MemoryVectorSyncWorkerStatus,
  MemoryVectorSyncSettings,
  StartMemoryVectorSyncResult,
} from "../src/settings/model/memoryVectorSyncService.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function status(overrides: Partial<MemoryVectorSyncWorkerStatus> = {}): MemoryVectorSyncWorkerStatus {
  return {
    lifeId: "life-from-authority",
    enabled: true,
    workerState: "stopped",
    runId: null,
    pendingCount: 0,
    processingCount: 0,
    retryWaitCount: 0,
    blockedCount: 0,
    failedCount: 0,
    lastRunAt: null,
    lastSuccessAt: null,
    lastSafeErrorCode: null,
    currentAction: null,
    nextRetryAt: null,
    ...overrides,
  };
}

function settings(overrides: Partial<MemoryVectorSyncSettings> = {}): MemoryVectorSyncSettings {
  return {
    lifeId: "life-from-authority",
    enabled: true,
    updatedAt: "2026-07-13T00:00:00Z",
    ...overrides,
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
  initialStatus: MemoryVectorSyncWorkerStatus,
  initialSettings: MemoryVectorSyncSettings,
) {
  const calls = { status: 0, settings: 0, setEnabled: 0, startSync: 0, pauseSync: 0, retry: 0 };
  const service: IMemoryVectorSyncService = {
    async getSettings() {
      calls.settings += 1;
      return initialSettings;
    },
    async setEnabled(_lifeId: string, enabled: boolean) {
      calls.setEnabled += 1;
      initialSettings.enabled = enabled;
      return initialSettings;
    },
    async getStatus() {
      calls.status += 1;
      return initialStatus;
    },
    async startSync() {
      calls.startSync += 1;
      initialStatus.workerState = "running";
      return { runId: "run-1", accepted: true };
    },
    async pauseSync() {
      calls.pauseSync += 1;
      return { ...initialStatus, workerState: "pausing" as const };
    },
    async retryFailures() {
      calls.retry += 1;
      return 1;
    },
  };
  return { calls, service };
}

const lifeService: ICurrentLifeService = {
  async getCurrentLife() {
    return { id: "life-from-authority" };
  },
};

test("sync panel loads status and settings but does not start sync automatically", async () => {
  const { calls, service } = createService(status(), settings());
  const controller = new MemoryVectorSyncController(service, lifeService, new FakeTimerScheduler());
  await controller.activate();
  assert.equal(calls.status, 1);
  assert.equal(calls.settings, 1);
  assert.equal(calls.startSync, 0);
  assert.equal(controller.canStart, true);
});

test("disabled sync disables start button", async () => {
  const disabledStatus = status({ enabled: false });
  const disabledSettings = settings({ enabled: false });
  const { calls, service } = createService(disabledStatus, disabledSettings);
  const controller = new MemoryVectorSyncController(service, lifeService, new FakeTimerScheduler());
  await controller.activate();
  assert.equal(controller.canStart, false);
});

test("toggling enabled updates state without starting sync", async () => {
  const { calls, service } = createService(status({ enabled: false }), settings({ enabled: false }));
  const controller = new MemoryVectorSyncController(service, lifeService, new FakeTimerScheduler());
  await controller.activate();
  assert.equal(controller.settings?.enabled, false);
  
  await controller.toggleEnabled(true);
  assert.equal(calls.setEnabled, 1);
  assert.equal(calls.startSync, 0);
  assert.equal(controller.settings?.enabled, true);
});

test("starting sync enters polling state", async () => {
  const timers = new FakeTimerScheduler();
  const { calls, service } = createService(status(), settings());
  const controller = new MemoryVectorSyncController(service, lifeService, timers);
  await controller.activate();
  
  await controller.startSync();
  assert.equal(calls.startSync, 1);
  assert.equal(controller.state, "polling");
  assert.equal(timers.callbacks.size, 1);
});

test("pausing sync transitions to pausing state and keeps polling", async () => {
  const timers = new FakeTimerScheduler();
  const runningStatus = status({ workerState: "running" });
  const { calls, service } = createService(runningStatus, settings());
  const controller = new MemoryVectorSyncController(service, lifeService, timers);
  await controller.activate();
  
  assert.equal(controller.canPause, true);
  await controller.pauseSync();
  assert.equal(calls.pauseSync, 1);
  assert.equal(controller.state, "polling");
});

test("retry requires failed or blocked items and refreshes status", async () => {
  const timers = new FakeTimerScheduler();
  const blockedStatus = status({ blockedCount: 1 });
  const { calls, service } = createService(blockedStatus, settings());
  const controller = new MemoryVectorSyncController(service, lifeService, timers);
  await controller.activate();
  
  assert.equal(controller.canRetry, true);
  await controller.retryFailures();
  assert.equal(calls.retry, 1);
  assert.equal(calls.status, 2); // 1 initial + 1 refresh
  assert.equal(calls.startSync, 0);
});

test("service DTOs and panel never expose request secrets, paths, memory text, or vectors", () => {
  const serviceSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/memoryVectorSyncService.ts"),
    "utf8",
  );
  const panelSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/MemoryVectorSyncPanel.vue"),
    "utf8",
  );
  assert.doesNotMatch(serviceSource, /apiKey|baseUrl|lanceDbPath|vectorSpace|memoryContent|memory_content/i);
  assert.doesNotMatch(panelSource, /apiKey|baseUrl|credential manager|currentDirectory|memoryContent|memory_content/i);
});

test("panel stops polling on visibility and unmount", () => {
  const panelSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/MemoryVectorSyncPanel.vue"),
    "utf8",
  );
  assert.match(panelSource, /document\.hidden/);
  assert.match(panelSource, /controller\.value\.deactivate\(\)/);
  assert.match(panelSource, /onUnmounted/);
});

test("settings capability has sync commands while chat and main do not", () => {
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
  assert.match(settings, /get_memory_vector_sync_settings/);
  assert.match(settings, /set_memory_vector_sync_enabled/);
  assert.match(settings, /get_memory_vector_sync_status/);
  assert.match(settings, /start_memory_vector_sync/);
  assert.match(settings, /pause_memory_vector_sync/);
  assert.match(settings, /retry_memory_vector_sync_failures/);
  assert.doesNotMatch(chat, /memory_vector_sync/);
  assert.doesNotMatch(main, /memory_vector_sync/);
});
