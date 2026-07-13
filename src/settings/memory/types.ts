export type MemoryStatus = "candidate" | "confirmed";
export type ManagedMemoryStatus = MemoryStatus | "all";
export type MemoryKind =
  | "experience"
  | "preference"
  | "fact"
  | "relationship"
  | "goal"
  | "skill"
  | "other";
export type MemorySource = "manual" | "conversation" | "system" | "import";
export type MemoryRevisionChangeType = "confirmed" | "edited" | "sensitivity_changed";

export interface MemoryListCursor {
  updatedAt: string;
  id: string;
}

export interface ManagedMemory {
  id: string;
  status: MemoryStatus;
  kind: MemoryKind;
  summary: string | null;
  isSensitive: boolean;
  revision: number;
  updatedAt: string;
}

export interface ManagedMemoryDetail extends ManagedMemory {
  content: string;
  source: MemorySource;
  importance: number;
  confidence: number;
  createdAt: string;
  revisionCount: number;
}

export interface MemoryRevision {
  revision: number;
  kind: MemoryKind;
  content: string;
  summary: string | null;
  isSensitive: boolean;
  changeType: MemoryRevisionChangeType;
  createdAt: string;
}

export interface MemoryListRequest {
  status?: ManagedMemoryStatus;
  kind?: MemoryKind;
  sensitive?: boolean;
  query?: string;
  pageSize?: number;
  cursor?: MemoryListCursor;
}

export interface MemoryListResult {
  items: ManagedMemory[];
  nextCursor: MemoryListCursor | null;
}

export interface UpdateConfirmedMemoryRequest {
  memoryId: string;
  expectedRevision: number;
  kind: MemoryKind;
  content: string;
  summary?: string | null;
}

export interface SetMemorySensitiveRequest {
  memoryId: string;
  expectedRevision: number;
  isSensitive: boolean;
}

export interface DeleteMemoryRequest {
  memoryId: string;
  expectedRevision: number;
}

export interface DeleteMemoryResult {
  memoryId: string;
  deleted: boolean;
}

export type MemoryManagementErrorCode =
  | "MEMORY_NOT_FOUND"
  | "MEMORY_LIFE_MISMATCH"
  | "MEMORY_NOT_CONFIRMED"
  | "MEMORY_REVISION_CONFLICT"
  | "INVALID_MEMORY_CONTENT"
  | "INVALID_MEMORY_KIND"
  | "INVALID_MEMORY_QUERY"
  | "MEMORY_DELETE_CONFLICT"
  | "MEMORY_STORAGE_UNAVAILABLE"
  | "INTERNAL_ERROR";

export interface MemoryManagementError {
  code: MemoryManagementErrorCode;
  message: string;
  recoverable: boolean;
}
