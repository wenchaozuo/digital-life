import { storageService } from "../../storage/storageService.ts";
import {
  memoryVectorIndexService,
  type IMemoryVectorIndexService,
  type MemoryVectorIndexStatus,
  type VectorIndexError,
  type VectorIndexErrorCode,
  type VectorIndexJobId,
  type VectorIndexJobResult,
  type VectorIndexJobStatus,
  type VectorIndexOperation,
} from "./memoryVectorIndexService.ts";

export type MemoryVectorIndexPanelState =
  | "idle"
  | "loadingStatus"
  | "ready"
  | "confirmingRebuild"
  | "starting"
  | "polling"
  | "cancelling"
  | "completed"
  | "cancelled"
  | "failed";

export interface ICurrentLifeService {
  getCurrentLife(): Promise<{ id: string } | undefined>;
}

export interface TimerScheduler {
  set(callback: () => void, delayMs: number): ReturnType<typeof setTimeout>;
  clear(handle: ReturnType<typeof setTimeout>): void;
}

const POLL_INTERVAL_MS = 1_000;
const runningStatuses: readonly VectorIndexJobStatus[] = [
  "queued",
  "resolvingProfile",
  "scanning",
  "embedding",
  "writing",
];

const browserTimers: TimerScheduler = {
  set(callback, delayMs) {
    return window.setTimeout(callback, delayMs);
  },
  clear(handle) {
    window.clearTimeout(handle);
  },
};

export class MemoryVectorIndexController {
  state: MemoryVectorIndexPanelState = "idle";
  status?: MemoryVectorIndexStatus;
  job?: VectorIndexJobResult;
  error?: VectorIndexError;
  lifeId?: string;
  cancelRequested = false;

  private pollTimer?: ReturnType<typeof setTimeout>;
  private active = false;
  private readonly indexService: IMemoryVectorIndexService;
  private readonly lifeService: ICurrentLifeService;
  private readonly timers: TimerScheduler;

  constructor(
    indexService: IMemoryVectorIndexService = memoryVectorIndexService,
    lifeService: ICurrentLifeService = storageService,
    timers: TimerScheduler = browserTimers,
  ) {
    this.indexService = indexService;
    this.lifeService = lifeService;
    this.timers = timers;
  }

  get canStartRebuild(): boolean {
    return Boolean(
      this.lifeId &&
        this.status?.activeEmbeddingProfileExists &&
        this.status.credentialExists &&
        !this.status.rebuildRunning &&
        !this.isRunningJob &&
        this.state !== "starting" &&
        this.state !== "cancelling",
    );
  }

  get isRunningJob(): boolean {
    return this.job !== undefined && isRunningStatus(this.job.status);
  }

  get canCancelJob(): boolean {
    return this.isRunningJob && !this.cancelRequested;
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
        this.job = undefined;
        this.stopPolling();
        this.state = "ready";
        return;
      }
      this.lifeId = life.id;
      this.status = await this.indexService.getStatus(life.id);
      if (this.status.lastJob) {
        this.job = this.status.lastJob;
      }
      this.state = "ready";
      if (this.active && this.job && isRunningStatus(this.job.status)) {
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

  requestRebuildConfirmation(): boolean {
    if (!this.canStartRebuild) {
      return false;
    }
    this.state = "confirmingRebuild";
    this.error = undefined;
    return true;
  }

  cancelRebuildConfirmation(): void {
    if (this.state === "confirmingRebuild") {
      this.state = "ready";
    }
  }

  async confirmRebuild(): Promise<boolean> {
    if (this.state !== "confirmingRebuild" || !this.lifeId) {
      return false;
    }
    this.state = "starting";
    this.error = undefined;
    try {
      const jobId = await this.indexService.startRebuild(this.lifeId);
      this.job = pendingJob(jobId, this.lifeId);
      this.cancelRequested = false;
      this.state = "polling";
      this.startPolling(true);
      return true;
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "startRebuild");
      this.state = "failed";
      if (this.error.code === "REBUILD_ALREADY_RUNNING") {
        await this.refreshStatus();
      }
      return false;
    }
  }

  async requestCancel(): Promise<boolean> {
    if (!this.canCancelJob || !this.job) {
      return false;
    }
    this.state = "cancelling";
    this.cancelRequested = true;
    this.error = undefined;
    try {
      this.job = await this.indexService.cancelJob(this.job.jobId);
      this.state = "polling";
      this.startPolling(true);
      return true;
    } catch (caught: unknown) {
      this.cancelRequested = false;
      this.error = errorFromUnknown(caught, "cancelJob");
      this.state = "failed";
      this.stopPolling();
      return false;
    }
  }

  private startPolling(immediate = false): void {
    if (!this.active || !this.job || !isRunningStatus(this.job.status)) {
      return;
    }
    this.stopPolling();
    const delay = immediate ? 0 : POLL_INTERVAL_MS;
    this.pollTimer = this.timers.set(() => {
      this.pollTimer = undefined;
      void this.pollJob();
    }, delay);
  }

  private stopPolling(): void {
    if (this.pollTimer !== undefined) {
      this.timers.clear(this.pollTimer);
      this.pollTimer = undefined;
    }
  }

  private async pollJob(): Promise<void> {
    if (!this.active || !this.job || !isRunningStatus(this.job.status)) {
      return;
    }
    this.state = "polling";
    try {
      this.job = await this.indexService.getJob(this.job.jobId);
      if (isRunningStatus(this.job.status)) {
        this.startPolling();
        return;
      }
      this.cancelRequested = false;
      this.stopPolling();
      const terminalState: MemoryVectorIndexPanelState =
        this.job.status === "completed"
          ? "completed"
          : this.job.status === "cancelled"
            ? "cancelled"
            : "failed";
      this.state = terminalState;
      if (this.job.status === "failed" || this.job.status === "cancelled") {
        this.error = jobError(this.job);
      }
      await this.refreshStatus();
      if (!this.error) {
        this.state = terminalState;
      }
    } catch (caught: unknown) {
      this.error = errorFromUnknown(caught, "pollJob");
      this.state = "failed";
      this.stopPolling();
    }
  }
}

export function isRunningStatus(status: VectorIndexJobStatus): boolean {
  return runningStatuses.includes(status);
}

export function errorFromUnknown(
  caught: unknown,
  operation: VectorIndexOperation,
): VectorIndexError {
  const record = errorRecord(caught);
  if (record) {
    const code = vectorIndexErrorCode(record.code);
    return {
      code,
      safeMessage: guidanceFor(code),
      operation,
      recoverable: true,
    };
  }
  return {
    code: "VECTOR_INDEX_UI_ERROR",
    safeMessage: "The memory vector index operation could not be completed.",
    operation,
    recoverable: true,
  };
}

function jobError(job: VectorIndexJobResult): VectorIndexError {
  const code = job.errorCode ?? (job.status === "cancelled" ? "REBUILD_CANCELLED" : "REBUILD_FAILED");
  return {
    code,
    safeMessage: job.errorMessage ?? guidanceFor(code),
    operation: "pollJob",
    recoverable: true,
  };
}

function guidanceFor(code: VectorIndexErrorCode): string {
  switch (code) {
    case "NO_ACTIVE_EMBEDDING_PROFILE":
      return "Set an active Embedding model profile before rebuilding the index.";
    case "EMBEDDING_CREDENTIAL_NOT_FOUND":
      return "Save an API Key for the active Embedding model profile before rebuilding.";
    case "EMBEDDING_DIMENSION_MISMATCH":
      return "Check the configured embedding dimension and the model's actual dimension.";
    case "VECTOR_STORE_UNAVAILABLE":
      return "The derived index storage is unavailable. Check the configured storage location.";
    case "REBUILD_ALREADY_RUNNING":
      return "A rebuild is already running. Restoring its task status instead.";
    case "REBUILD_CANCELLED":
      return "The rebuild was cancelled. Run a complete rebuild again if the index needs recovery.";
    default:
      return "The memory vector index operation could not be completed.";
  }
}

function vectorIndexErrorCode(value: unknown): VectorIndexErrorCode {
  const codes: readonly VectorIndexErrorCode[] = [
    "INVALID_REQUEST",
    "NO_ACTIVE_EMBEDDING_PROFILE",
    "EMBEDDING_PROFILE_NOT_FOUND",
    "EMBEDDING_CREDENTIAL_NOT_FOUND",
    "EMBEDDING_PURPOSE_MISMATCH",
    "UNSUPPORTED_EMBEDDING_PROVIDER",
    "EMBEDDING_DIMENSION_MISMATCH",
    "VECTOR_STORE_UNAVAILABLE",
    "REBUILD_ALREADY_RUNNING",
    "REBUILD_CANCELLED",
    "REBUILD_FAILED",
    "JOB_NOT_FOUND",
  ];
  return typeof value === "string" && codes.includes(value as VectorIndexErrorCode)
    ? (value as VectorIndexErrorCode)
    : "VECTOR_INDEX_UI_ERROR";
}

function pendingJob(jobId: VectorIndexJobId, lifeId: string): VectorIndexJobResult {
  return {
    jobId,
    lifeId,
    status: "queued",
    progress: {
      scannedCount: 0,
      eligibleCount: 0,
      embeddedCount: 0,
      indexedCount: 0,
      skippedCandidateCount: 0,
      skippedSensitiveCount: 0,
      currentBatch: 0,
      totalBatches: 0,
      embeddingModel: null,
      dimension: null,
    },
    report: null,
    errorCode: null,
    errorMessage: null,
  };
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
