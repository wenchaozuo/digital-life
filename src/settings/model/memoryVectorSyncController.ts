import { storageService } from "../../storage/storageService.ts";
import {
  memoryVectorSyncService,
  type IMemoryVectorSyncService,
  type MemoryVectorSyncSettings,
  type MemoryVectorSyncWorkerErrorCode,
  type MemoryVectorSyncWorkerStatus,
} from "./memoryVectorSyncService.ts";

export type MemoryVectorSyncPanelState =
  | "idle"
  | "loadingStatus"
  | "ready"
  | "starting"
  | "polling"
  | "pausing"
  | "failed";

export interface ICurrentLifeService {
  getCurrentLife(): Promise<{ id: string } | undefined>;
}

export interface TimerScheduler {
  set(callback: () => void, delayMs: number): ReturnType<typeof setTimeout>;
  clear(handle: ReturnType<typeof setTimeout>): void;
}

const POLL_INTERVAL_MS = 1_000;

const browserTimers: TimerScheduler = {
  set(callback, delayMs) {
    return window.setTimeout(callback, delayMs);
  },
  clear(handle) {
    window.clearTimeout(handle);
  },
};

export type SyncOperation = "loadStatus" | "startSync" | "pauseSync" | "retryFailures" | "pollStatus" | "setEnabled";

export interface SyncError {
  operation: SyncOperation;
  code: MemoryVectorSyncWorkerErrorCode | "SYNC_UI_ERROR";
  safeMessage: string;
  recoverable: boolean;
}

export class MemoryVectorSyncController {
  state: MemoryVectorSyncPanelState = "idle";
  settings?: MemoryVectorSyncSettings;
  status?: MemoryVectorSyncWorkerStatus;
  error?: SyncError;
  lifeId?: string;

  private pollTimer?: ReturnType<typeof setTimeout>;
  private active = false;
  private readonly syncService: IMemoryVectorSyncService;
  private readonly lifeService: ICurrentLifeService;
  private readonly timers: TimerScheduler;

  constructor(
    syncService: IMemoryVectorSyncService = memoryVectorSyncService,
    lifeService: ICurrentLifeService = storageService,
    timers: TimerScheduler = browserTimers,
  ) {
    this.syncService = syncService;
    this.lifeService = lifeService;
    this.timers = timers;
  }

  get isRunning(): boolean {
    return this.status?.workerState === "running" || this.status?.workerState === "pausing";
  }

  get canStart(): boolean {
    return Boolean(
      this.lifeId &&
        this.status?.enabled &&
        !this.isRunning &&
        this.state !== "starting" &&
        this.state !== "pausing"
    );
  }

  get canPause(): boolean {
    return this.isRunning && this.state !== "pausing";
  }

  get canRetry(): boolean {
    return Boolean(
      this.lifeId &&
        ((this.status?.failedCount ?? 0) > 0 || (this.status?.blockedCount ?? 0) > 0)
    );
  }

  async activate(): Promise<void> {
    this.active = true;
    await this.refreshStatus();
  }

  deactivate(): void {
    this.active = false;
    this.stopPolling();
  }

  async refreshStatus(): Promise<void> {
    this.state = "loadingStatus";
    this.error = undefined;
    try {
      const life = await this.lifeService.getCurrentLife();
      if (!life) {
        this.lifeId = undefined;
        this.status = undefined;
        this.settings = undefined;
        this.stopPolling();
        this.state = "ready";
        return;
      }
      this.lifeId = life.id;
      
      const [settings, status] = await Promise.all([
        this.syncService.getSettings(life.id),
        this.syncService.getStatus(life.id),
      ]);
      
      this.settings = settings;
      this.status = status;
      this.state = "ready";
      
      if (this.active && this.isRunning) {
        this.startPolling();
      } else {
        this.stopPolling();
      }
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "loadStatus");
      this.state = "failed";
      this.stopPolling();
    }
  }

  async toggleEnabled(enabled: boolean): Promise<boolean> {
    if (!this.lifeId) return false;
    this.error = undefined;
    try {
      this.settings = await this.syncService.setEnabled(this.lifeId, enabled);
      await this.refreshStatus();
      return true;
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "setEnabled");
      this.state = "failed";
      return false;
    }
  }

  async startSync(): Promise<boolean> {
    if (!this.canStart || !this.lifeId) {
      return false;
    }
    this.state = "starting";
    this.error = undefined;
    try {
      await this.syncService.startSync(this.lifeId);
      this.state = "polling";
      this.startPolling(true);
      return true;
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "startSync");
      this.state = "failed";
      return false;
    }
  }

  async pauseSync(): Promise<boolean> {
    if (!this.canPause || !this.lifeId) {
      return false;
    }
    this.state = "pausing";
    this.error = undefined;
    try {
      this.status = await this.syncService.pauseSync(this.lifeId);
      this.state = "polling";
      this.startPolling(true);
      return true;
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "pauseSync");
      this.state = "failed";
      return false;
    }
  }

  async retryFailures(): Promise<boolean> {
    if (!this.canRetry || !this.lifeId) {
      return false;
    }
    this.error = undefined;
    try {
      await this.syncService.retryFailures(this.lifeId);
      await this.refreshStatus();
      return true;
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "retryFailures");
      this.state = "failed";
      return false;
    }
  }

  private startPolling(immediate = false): void {
    if (!this.active || !this.isRunning) {
      return;
    }
    this.stopPolling();
    const delay = immediate ? 0 : POLL_INTERVAL_MS;
    this.pollTimer = this.timers.set(() => {
      this.pollTimer = undefined;
      void this.pollStatus();
    }, delay);
  }

  private stopPolling(): void {
    if (this.pollTimer !== undefined) {
      this.timers.clear(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  private async pollStatus(): Promise<void> {
    if (!this.active || !this.lifeId) {
      return;
    }
    this.state = "polling";
    try {
      this.status = await this.syncService.getStatus(this.lifeId);
      if (this.isRunning) {
        this.startPolling();
      } else {
        this.stopPolling();
        this.state = "ready";
      }
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "pollStatus");
      this.state = "failed";
      this.stopPolling();
    }
  }
}

export function errorFromUnknown(
  caught: unknown,
  operation: SyncOperation,
): SyncError {
  const record = errorRecord(caught);
  if (record) {
    const code = syncErrorCode(record.code);
    const recoverable = typeof record.recoverable === "boolean" ? record.recoverable : true;
    return {
      code,
      safeMessage: guidanceFor(code),
      operation,
      recoverable
    };
  }
  return {
    code: "SYNC_UI_ERROR",
    safeMessage: "The memory vector sync operation could not be completed.",
    operation,
    recoverable: true
  };
}

function guidanceFor(code: MemoryVectorSyncWorkerErrorCode | "SYNC_UI_ERROR"): string {
  switch (code) {
    case "NO_ACTIVE_EMBEDDING_PROFILE":
      return "Set an active Embedding model profile before syncing memory vectors.";
    case "EMBEDDING_CREDENTIAL_NOT_FOUND":
      return "Save an API Key for the active Embedding model profile before syncing.";
    case "VECTOR_STORE_UNAVAILABLE":
      return "The derived index storage is unavailable. Check the configured storage location.";
    case "INDEX_OPERATION_BUSY":
      return "A full rebuild or another index operation is currently running. Try again later.";
    case "SYNC_DISABLED":
      return "Incremental sync is disabled. Enable it to start syncing.";
    default:
      return "The memory vector sync operation could not be completed.";
  }
}

function syncErrorCode(value: unknown): MemoryVectorSyncWorkerErrorCode | "SYNC_UI_ERROR" {
  const codes: readonly MemoryVectorSyncWorkerErrorCode[] = [
    "INVALID_REQUEST",
    "SYNC_DISABLED",
    "SYNC_ALREADY_RUNNING",
    "SYNC_NOT_RUNNING",
    "INDEX_OPERATION_BUSY",
    "OUTBOX_UNAVAILABLE",
    "REPOSITORY_UNAVAILABLE",
    "NO_ACTIVE_EMBEDDING_PROFILE",
    "EMBEDDING_PROFILE_NOT_FOUND",
    "EMBEDDING_CREDENTIAL_NOT_FOUND",
    "EMBEDDING_PURPOSE_MISMATCH",
    "INVALID_EMBEDDING_PROFILE",
    "UNSUPPORTED_EMBEDDING_PROVIDER",
    "AUTHENTICATION_FAILED",
    "RATE_LIMITED",
    "NETWORK_UNAVAILABLE",
    "REQUEST_TIMEOUT",
    "INVALID_PROVIDER_RESPONSE",
    "VECTOR_STORE_UNAVAILABLE",
    "INTERNAL_ERROR"
  ];
  return typeof value === "string" && codes.includes(value as MemoryVectorSyncWorkerErrorCode)
    ? (value as MemoryVectorSyncWorkerErrorCode)
    : "SYNC_UI_ERROR";
}

function isErrorRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function errorRecord(value: unknown): Record<string, unknown> | undefined {
  if (isErrorRecord(value)) {
    return value;
  }
  if (typeof value !== "string") {
    return undefined;
  }
  try {
    const parsed: unknown = JSON.parse(value);
    return isErrorRecord(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}
