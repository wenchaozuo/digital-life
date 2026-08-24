import { storageService } from "../../storage/storageService.ts";
import {
  memoryVectorSyncService,
  type IMemoryVectorSyncService,
  type MemoryVectorSyncDrainResult,
  type MemoryVectorSyncSettings,
  type MemoryVectorSyncWorkerErrorCode,
  type MemoryVectorSyncWorkerStatus,
} from "./memoryVectorSyncService.ts";

export type MemoryVectorSyncPanelState =
  | "idle"
  | "loadingStatus"
  | "ready"
  | "starting"
  | "failed";

export interface ICurrentLifeService {
  getCurrentLife(): Promise<{ id: string } | undefined>;
}

export type SyncOperation = "loadStatus" | "startSync" | "retryFailures" | "setEnabled";

export interface SyncError {
  operation: SyncOperation;
  code: MemoryVectorSyncWorkerErrorCode | "SYNC_UI_ERROR";
  safeMessage: string;
  recoverable: boolean;
}

/**
 * Settings controller for ONE bounded fenced drain per manual start.
 *
 * The frozen production entrypoint `start_fenced_vector_sync_drain` is a
 * bounded IPC operation: it returns only after processing at most `limit`
 * items, and it has NO background-worker run id. The controller must never
 * enter the legacy `start -> polling -> pause background worker` state
 * machine; after the drain returns, authoritative Settings/status counts are
 * refreshed once and the panel returns to `ready`.
 */
export class MemoryVectorSyncController {
  state: MemoryVectorSyncPanelState = "idle";
  settings?: MemoryVectorSyncSettings;
  status?: MemoryVectorSyncWorkerStatus;
  error?: SyncError;
  lifeId?: string;
  /** Count-only result of the most recent manual bounded fenced drain. */
  lastDrainResult?: MemoryVectorSyncDrainResult;

  private readonly syncService: IMemoryVectorSyncService;
  private readonly lifeService: ICurrentLifeService;

  constructor(
    syncService: IMemoryVectorSyncService = memoryVectorSyncService,
    lifeService: ICurrentLifeService = storageService,
  ) {
    this.syncService = syncService;
    this.lifeService = lifeService;
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
        this.state !== "loadingStatus" &&
        this.state !== "failed"
    );
  }

  get canRetry(): boolean {
    return Boolean(
      this.lifeId &&
        ((this.status?.failedCount ?? 0) > 0 || (this.status?.blockedCount ?? 0) > 0)
    );
  }

  async activate(): Promise<void> {
    await this.refreshStatus();
  }

  /**
   * Panel lifecycle hook (visibility/unmount). The bounded drain flow keeps
   * no timers or background state, so there is nothing to stop; the panel
   * simply re-reads authoritative counts the next time it activates.
   */
  deactivate(): void {
    // Intentionally empty: no polling timer or background worker state exists.
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
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "loadStatus");
      this.state = "failed";
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
      // ONE bounded fenced drain. The backend returns only after the bounded
      // invocation completes (or fails); there is no run id and nothing to
      // poll, so the panel refreshes authoritative counts once and returns
      // to `ready`.
      this.lastDrainResult = await this.syncService.startSync();
      await this.refreshStatus();
      return true;
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "startSync");
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
    case "UNAVAILABLE":
      return "The fenced vector sync execution is currently unavailable. Try again later.";
    case "DRAIN_FAILED":
      return "The bounded vector sync drain could not complete. Check model, credential, and storage configuration, then try again.";
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
    "UNAVAILABLE",
    "DRAIN_FAILED",
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