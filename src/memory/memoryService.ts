import { invoke } from "@tauri-apps/api/core";
import type {
  ConfirmMemoryRequest,
  CreateMemoryCandidateRequest,
  DeleteMemoryResult,
  MemoryQuery,
  MemoryRecord,
  UpdateMemoryRequest,
} from "./types";

export class MemoryServiceError extends Error {
  readonly code: string;
  readonly recoverable: boolean;

  constructor(code: string, message: string, recoverable: boolean) {
    super(message);
    this.name = "MemoryServiceError";
    this.code = code;
    this.recoverable = recoverable;
  }
}

export class MemoryService {
  async createCandidate(
    request: CreateMemoryCandidateRequest,
  ): Promise<MemoryRecord> {
    return this.invokeMemory<MemoryRecord>("create_memory_candidate", {
      request,
    });
  }

  async list(query: MemoryQuery): Promise<readonly MemoryRecord[]> {
    return this.invokeMemory<MemoryRecord[]>("list_memories", { query });
  }

  async get(lifeId: string, memoryId: string): Promise<MemoryRecord> {
    return this.invokeMemory<MemoryRecord>("get_memory", {
      lifeId,
      memoryId,
    });
  }

  async updateCandidate(request: UpdateMemoryRequest): Promise<MemoryRecord> {
    return this.invokeMemory<MemoryRecord>("update_memory_candidate", {
      request,
    });
  }

  async confirm(request: ConfirmMemoryRequest): Promise<MemoryRecord> {
    return this.invokeMemory<MemoryRecord>("confirm_memory", { request });
  }

  async delete(
    lifeId: string,
    memoryId: string,
  ): Promise<DeleteMemoryResult> {
    return this.invokeMemory<DeleteMemoryResult>("delete_memory", {
      lifeId,
      memoryId,
    });
  }

  private async invokeMemory<T>(
    command: string,
    args: Record<string, unknown>,
  ): Promise<T> {
    try {
      return await invoke<T>(command, args);
    } catch (error: unknown) {
      throw toMemoryServiceError(error);
    }
  }
}

export function toMemoryServiceError(error: unknown): MemoryServiceError {
  if (isRecord(error)) {
    const code = typeof error.code === "string" ? error.code : "MEMORY_ERROR";
    const message =
      typeof error.message === "string"
        ? error.message
        : "The memory operation could not be completed.";
    const recoverable =
      typeof error.recoverable === "boolean" ? error.recoverable : true;
    return new MemoryServiceError(code, message, recoverable);
  }

  return new MemoryServiceError(
    "MEMORY_ERROR",
    "The memory operation could not be completed.",
    true,
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

export const memoryService = new MemoryService();
