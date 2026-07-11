import type { MemoryKind } from "../types";

export interface RetrievalQuery {
  lifeId: string;
  queryText: string;
  kinds?: readonly MemoryKind[];
  limit: number;
}

export interface MemoryRetrievalResult {
  memoryId: string;
  kind: MemoryKind;
  content: string;
  summary?: string;
  importance: number;
  confidence: number;
  createdAt: string;
}

export type RetrievalResult = MemoryRetrievalResult;
