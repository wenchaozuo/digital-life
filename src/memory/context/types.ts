import type { MemoryRetrievalResult } from "../retrieval/types";

export interface MemoryContextInput {
  memories: readonly MemoryRetrievalResult[];
  maxMemories?: number;
  characterBudget?: number;
}

export interface MemoryContextResult {
  context: string | null;
  retrievedCount: number;
  usedCount: number;
  usedMemoryIds: readonly string[];
  truncated: boolean;
}
