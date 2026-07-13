import { invoke } from "@tauri-apps/api/core";

import type {
  DeleteMemoryRequest,
  DeleteMemoryResult,
  ManagedMemoryDetail,
  MemoryListRequest,
  MemoryListResult,
  MemoryRevision,
  SetMemorySensitiveRequest,
  UpdateConfirmedMemoryRequest,
} from "./types.ts";

export interface IMemoryManagementService {
  list(request?: MemoryListRequest): Promise<MemoryListResult>;
  get(memoryId: string): Promise<ManagedMemoryDetail>;
  listRevisions(memoryId: string): Promise<MemoryRevision[]>;
  update(request: UpdateConfirmedMemoryRequest): Promise<ManagedMemoryDetail>;
  setSensitive(request: SetMemorySensitiveRequest): Promise<ManagedMemoryDetail>;
  deletePermanently(request: DeleteMemoryRequest): Promise<DeleteMemoryResult>;
}

export class MemoryManagementService implements IMemoryManagementService {
  list(request: MemoryListRequest = {}): Promise<MemoryListResult> {
    return invoke<MemoryListResult>("list_managed_memories", { request });
  }

  get(memoryId: string): Promise<ManagedMemoryDetail> {
    return invoke<ManagedMemoryDetail>("get_managed_memory", {
      request: { memoryId },
    });
  }

  listRevisions(memoryId: string): Promise<MemoryRevision[]> {
    return invoke<MemoryRevision[]>("list_memory_revisions", {
      request: { memoryId },
    });
  }

  update(request: UpdateConfirmedMemoryRequest): Promise<ManagedMemoryDetail> {
    return invoke<ManagedMemoryDetail>("update_confirmed_memory", { request });
  }

  setSensitive(request: SetMemorySensitiveRequest): Promise<ManagedMemoryDetail> {
    return invoke<ManagedMemoryDetail>("set_memory_sensitive", { request });
  }

  deletePermanently(request: DeleteMemoryRequest): Promise<DeleteMemoryResult> {
    return invoke<DeleteMemoryResult>("delete_memory_permanently", { request });
  }
}

export const memoryManagementService = new MemoryManagementService();
