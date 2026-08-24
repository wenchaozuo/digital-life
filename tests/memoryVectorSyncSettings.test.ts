import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MemoryVectorSyncController,
  type ICurrentLifeService,
} from "../src/settings/model/memoryVectorSyncController.ts";
import type {
  IMemoryVectorSyncService,
  MemoryVectorSyncDrainResult,
  MemoryVectorSyncWorkerStatus,
  MemoryVectorSyncSettings,
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

function drainResult(overrides: Partial<MemoryVectorSyncDrainResult> = {}): MemoryVectorSyncDrainResult {
  return {
    requestedLimit: 32,
    processed: 3,
    appliedUpserts: 2,
    appliedDeletes: 1,
    retryScheduled: 0,
    blocked: 0,
    failed: 0,
    stoppedNoEligible: false,
    stoppedLostLease: false,
    ...overrides,
  };
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
      return drainResult();
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
  const controller = new MemoryVectorSyncController(service, lifeService);
  await controller.activate();
  assert.equal(calls.status, 1);
  assert.equal(calls.settings, 1);
  assert.equal(calls.startSync, 0);
  assert.equal(controller.canStart, true);
  assert.equal(controller.state, "ready");
});

test("disabled sync prevents manual start", async () => {
  const disabledStatus = status({ enabled: false });
  const disabledSettings = settings({ enabled: false });
  const { calls, service } = createService(disabledStatus, disabledSettings);
  const controller = new MemoryVectorSyncController(service, lifeService);
  await controller.activate();
  assert.equal(controller.canStart, false);
  assert.equal(calls.startSync, 0);
});

test("toggling enabled updates state without starting sync", async () => {
  const { calls, service } = createService(status({ enabled: false }), settings({ enabled: false }));
  const controller = new MemoryVectorSyncController(service, lifeService);
  await controller.activate();
  assert.equal(controller.settings?.enabled, false);
  
  await controller.toggleEnabled(true);
  assert.equal(calls.setEnabled, 1);
  assert.equal(calls.startSync, 0);
  assert.equal(controller.settings?.enabled, true);
});

test("user manual start invokes exactly one fenced drain and refreshes counts", async () => {
  const { calls, service } = createService(status({ pendingCount: 5 }), settings());
  const controller = new MemoryVectorSyncController(service, lifeService);
  await controller.activate();

  const ok = await controller.startSync();
  assert.equal(ok, true);
  assert.equal(calls.startSync, 1);
  // One initial load refresh + one post-drain authoritative refresh.
  assert.equal(calls.status, 2);
  assert.equal(calls.settings, 2);
  assert.equal(controller.state, "ready");
  assert.deepEqual(controller.lastDrainResult, drainResult());
});

test("successful start does not enter background-worker polling and needs no run id", async () => {
  const { calls, service } = createService(status(), settings());
  const controller = new MemoryVectorSyncController(service, lifeService);
  await controller.activate();

  assert.equal(controller.state, "ready");
  await controller.startSync();
  // The bounded fenced drain returns after completion: the panel goes back to
  // `ready` and never enters the legacy `polling`/`pausing` state machine.
  assert.equal(controller.state, "ready");
  assert.notEqual(controller.state, "polling");
  assert.notEqual(controller.state, "pausing");
  // Exactly one drain invocation; the next status call is the single refresh.
  assert.equal(calls.status, 2);
  // The count-only drain result carries no fake run-id/worker state.
  assert.ok(controller.lastDrainResult);
  assert.equal("runId" in controller.lastDrainResult, false);
  assert.equal("accepted" in controller.lastDrainResult, false);
  assert.equal("workerState" in controller.lastDrainResult, false);
});

test("retry requires failed or blocked items and refreshes status", async () => {
  const blockedStatus = status({ blockedCount: 1 });
  const { calls, service } = createService(blockedStatus, settings());
  const controller = new MemoryVectorSyncController(service, lifeService);
  await controller.activate();
  
  assert.equal(controller.canRetry, true);
  await controller.retryFailures();
  assert.equal(calls.retry, 1);
  assert.equal(calls.status, 2); // 1 initial + 1 refresh
  assert.equal(calls.startSync, 0);
});

test("service start invoke targets the fenced drain with a fresh lease owner and fixed limit", () => {
  const serviceSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/memoryVectorSyncService.ts"),
    "utf8",
  );
  assert.match(serviceSource, /start_fenced_vector_sync_drain/);
  assert.doesNotMatch(serviceSource, /start_memory_vector_sync/);
  assert.match(serviceSource, /MANUAL_SYNC_DRAIN_LIMIT = 32/);
  assert.match(serviceSource, /settings-ui:/);

  const startBlock = serviceSource.slice(
    serviceSource.indexOf("async startSync"),
    serviceSource.indexOf("async pauseSync"),
  );
  assert.match(startBlock, /leaseOwner/);
  assert.match(startBlock, /MANUAL_SYNC_DRAIN_LIMIT|limit:\s*32/);
  // The fenced start request must carry no authority/identity/secret fields.
  assert.doesNotMatch(
    startBlock,
    /lifeId|generationId|profileId|modelName|credential|apiKey|baseUrl|lanceDbPath|memoryContent|vectorSpace/i,
  );
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
  // The panel exposes no generation/provider/credential/path identity either.
  assert.doesNotMatch(
    panelSource,
    /generationId|generationName|profileId|providerId|providerName|modelName|leaseOwner|lanceDbPath|vectorSpace/i,
  );
});

test("manual start still requires explicit user confirmation in the panel", () => {
  const panelSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/MemoryVectorSyncPanel.vue"),
    "utf8",
  );
  assert.match(panelSource, /showStartConfirm/);
  assert.match(panelSource, /confirmStart/);
  assert.match(panelSource, /handleStart/);
});

test("panel is bounded-drain truthful and offers no pause control for the drain", () => {
  const panelSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/MemoryVectorSyncPanel.vue"),
    "utf8",
  );
  // No legacy pause control is presented as a drain control.
  assert.doesNotMatch(panelSource, /暂停同步/);
  assert.doesNotMatch(panelSource, /pauseSync/);
  // The product contract is stated truthfully: at most 32 items, not a
  // permanent background worker, and the user may start another run after
  // the bounded invocation returns.
  assert.match(panelSource, /最多处理 32 项/);
  assert.match(panelSource, /不是常驻后台进程/);
  assert.match(panelSource, /再次点击“开始同步”/);
  assert.match(panelSource, /processes at most 32 items/);
  assert.match(panelSource, /not a permanent background worker/);
});

test("panel deactivates on visibility change and unmount", () => {
  const panelSource = fs.readFileSync(
    path.join(__dirname, "../src/settings/model/MemoryVectorSyncPanel.vue"),
    "utf8",
  );
  assert.match(panelSource, /document\.hidden/);
  assert.match(panelSource, /controller\.value\.deactivate\(\)/);
  assert.match(panelSource, /onUnmounted/);
});

test("settings capability has sync commands while chat and main do not", () => {
  const settingsSource = fs.readFileSync(
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
  for (const command of [
    "get_memory_vector_sync_settings",
    "set_memory_vector_sync_enabled",
    "get_memory_vector_sync_status",
    "start_fenced_vector_sync_drain",
    "retry_memory_vector_sync_failures",
  ]) {
    assert.match(settingsSource, new RegExp(command));
  }
  // Legacy pause remains registered as a separate dormant control.
  assert.match(settingsSource, /pause_memory_vector_sync/);
  // The stale legacy background-worker start is NOT granted.
  assert.doesNotMatch(settingsSource, /start_memory_vector_sync/);
  // Chat and main receive none of the sync surface.
  assert.doesNotMatch(chat, /memory_vector_sync/);
  assert.doesNotMatch(main, /memory_vector_sync/);
  assert.doesNotMatch(chat, /start_fenced_vector_sync_drain/);
  assert.doesNotMatch(main, /start_fenced_vector_sync_drain/);
});