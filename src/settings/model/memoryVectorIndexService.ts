import { invoke } from "@tauri-apps/api/core";

export type VectorIndexJobId = string;

export type VectorIndexJobStatus =
  | "queued"
  | "resolvingProfile"
  | "scanning"
  | "embedding"
  | "writing"
  | "completed"
  | "failed"
  | "cancelled";

export interface VectorIndexJobProgress {
  scannedCount: number;
  eligibleCount: number;
  embeddedCount: number;
  indexedCount: number;
  skippedCandidateCount: number;
  skippedSensitiveCount: number;
  currentBatch: number;
  totalBatches: number;
  embeddingModel: string | null;
  dimension: number | null;
}

export interface VectorIndexJobReport {
  scannedCount: number;
  eligibleCount: number;
  indexedCount: number;
  skippedCandidateCount: number;
  skippedSensitiveCount: number;
  failedCount: number;
  embeddingModel: string;
  dimension: number;
  completed: boolean;
}

export interface VectorIndexJobResult {
  jobId: VectorIndexJobId;
  lifeId: string;
  status: VectorIndexJobStatus;
  progress: VectorIndexJobProgress;
  report: VectorIndexJobReport | null;
  errorCode: VectorIndexErrorCode | null;
  errorMessage: string | null;
}

export interface MemoryVectorIndexStatus {
  lifeId: string;
  activeEmbeddingProfileExists: boolean;
  credentialExists: boolean;
  embeddingModel: string | null;
  configuredDimension: number | null;
  indexDirectoryExists: boolean;
  indexedCount: number;
  eligibleMemoryCount: number;
  rebuildRunning: boolean;
  lastJob: VectorIndexJobResult | null;
  rebuildRecommended: boolean;
  reason: string | null;
}

export type VectorIndexErrorCode =
  | "INVALID_REQUEST"
  | "NO_ACTIVE_EMBEDDING_PROFILE"
  | "EMBEDDING_PROFILE_NOT_FOUND"
  | "EMBEDDING_CREDENTIAL_NOT_FOUND"
  | "EMBEDDING_PURPOSE_MISMATCH"
  | "UNSUPPORTED_EMBEDDING_PROVIDER"
  | "EMBEDDING_DIMENSION_MISMATCH"
  | "VECTOR_STORE_UNAVAILABLE"
  | "REBUILD_ALREADY_RUNNING"
  | "REBUILD_CANCELLED"
  | "REBUILD_FAILED"
  | "JOB_NOT_FOUND"
  | "VECTOR_INDEX_UI_ERROR";

export interface VectorIndexError {
  code: VectorIndexErrorCode;
  message: string;
  operation: VectorIndexOperation;
}

export type VectorIndexOperation = "loadStatus" | "startRebuild" | "pollJob" | "cancelJob";

export interface IMemoryVectorIndexService {
  getStatus(lifeId: string): Promise<MemoryVectorIndexStatus>;
  startRebuild(lifeId: string): Promise<VectorIndexJobId>;
  getJob(jobId: VectorIndexJobId): Promise<VectorIndexJobResult>;
  cancelJob(jobId: VectorIndexJobId): Promise<VectorIndexJobResult>;
}

export class MemoryVectorIndexService implements IMemoryVectorIndexService {
  async getStatus(lifeId: string): Promise<MemoryVectorIndexStatus> {
    return invoke<MemoryVectorIndexStatus>("get_memory_vector_index_status", {
      request: { lifeId },
    });
  }

  async startRebuild(lifeId: string): Promise<VectorIndexJobId> {
    return invoke<VectorIndexJobId>("start_memory_vector_index_rebuild", {
      request: { lifeId },
    });
  }

  async getJob(jobId: VectorIndexJobId): Promise<VectorIndexJobResult> {
    return invoke<VectorIndexJobResult>("get_memory_vector_index_job", {
      request: { jobId },
    });
  }

  async cancelJob(jobId: VectorIndexJobId): Promise<VectorIndexJobResult> {
    return invoke<VectorIndexJobResult>("cancel_memory_vector_index_job", {
      request: { jobId },
    });
  }
}

export const memoryVectorIndexService = new MemoryVectorIndexService();
