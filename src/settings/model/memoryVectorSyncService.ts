import { invoke } from "@tauri-apps/api/core";

export interface MemoryVectorSyncSettings {
  lifeId: string;
  enabled: boolean;
  updatedAt: string | null;
}

export type MemoryVectorSyncWorkerState = "stopped" | "running" | "pausing" | "paused";

export type MemoryVectorSyncWorkerErrorCode =
  | "INVALID_REQUEST"
  | "SYNC_DISABLED"
  | "SYNC_ALREADY_RUNNING"
  | "SYNC_NOT_RUNNING"
  | "INDEX_OPERATION_BUSY"
  | "OUTBOX_UNAVAILABLE"
  | "REPOSITORY_UNAVAILABLE"
  | "NO_ACTIVE_EMBEDDING_PROFILE"
  | "EMBEDDING_PROFILE_NOT_FOUND"
  | "EMBEDDING_CREDENTIAL_NOT_FOUND"
  | "EMBEDDING_PURPOSE_MISMATCH"
  | "INVALID_EMBEDDING_PROFILE"
  | "UNSUPPORTED_EMBEDDING_PROVIDER"
  | "AUTHENTICATION_FAILED"
  | "RATE_LIMITED"
  | "NETWORK_UNAVAILABLE"
  | "REQUEST_TIMEOUT"
  | "INVALID_PROVIDER_RESPONSE"
  | "VECTOR_STORE_UNAVAILABLE"
  | "INTERNAL_ERROR";

export type MemoryVectorSyncAction = "upsert" | "delete";

export interface MemoryVectorSyncWorkerStatus {
  lifeId: string;
  enabled: boolean;
  workerState: MemoryVectorSyncWorkerState;
  runId: string | null;
  pendingCount: number;
  processingCount: number;
  retryWaitCount: number;
  blockedCount: number;
  failedCount: number;
  lastRunAt: number | null;
  lastSuccessAt: number | null;
  lastSafeErrorCode: MemoryVectorSyncWorkerErrorCode | null;
  currentAction: MemoryVectorSyncAction | null;
  nextRetryAt: string | null;
}

export interface StartMemoryVectorSyncResult {
  runId: string;
  accepted: boolean;
}

export interface IMemoryVectorSyncService {
  getSettings(lifeId: string): Promise<MemoryVectorSyncSettings>;
  setEnabled(lifeId: string, enabled: boolean): Promise<MemoryVectorSyncSettings>;
  getStatus(lifeId: string): Promise<MemoryVectorSyncWorkerStatus>;
  startSync(lifeId: string): Promise<StartMemoryVectorSyncResult>;
  pauseSync(lifeId: string): Promise<MemoryVectorSyncWorkerStatus>;
  retryFailures(lifeId: string): Promise<number>;
}

export class MemoryVectorSyncService implements IMemoryVectorSyncService {
  async getSettings(lifeId: string): Promise<MemoryVectorSyncSettings> {
    return invoke<MemoryVectorSyncSettings>("get_memory_vector_sync_settings", { request: { lifeId } });
  }

  async setEnabled(lifeId: string, enabled: boolean): Promise<MemoryVectorSyncSettings> {
    return invoke<MemoryVectorSyncSettings>("set_memory_vector_sync_enabled", { request: { lifeId, enabled } });
  }

  async getStatus(lifeId: string): Promise<MemoryVectorSyncWorkerStatus> {
    return invoke<MemoryVectorSyncWorkerStatus>("get_memory_vector_sync_status", { request: { lifeId } });
  }

  async startSync(lifeId: string): Promise<StartMemoryVectorSyncResult> {
    return invoke<StartMemoryVectorSyncResult>("start_memory_vector_sync", { request: { lifeId } });
  }

  async pauseSync(lifeId: string): Promise<MemoryVectorSyncWorkerStatus> {
    return invoke<MemoryVectorSyncWorkerStatus>("pause_memory_vector_sync", { request: { lifeId } });
  }

  async retryFailures(lifeId: string): Promise<number> {
    return invoke<number>("retry_memory_vector_sync_failures", { request: { lifeId } });
  }
}

export const memoryVectorSyncService = new MemoryVectorSyncService();
