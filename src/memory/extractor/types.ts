import type { ConversationMessage } from "../../conversation/types";
import type {
  MemoryKind,
  MemorySourceTypes,
  MemoryStatuses,
} from "../types.ts";

export type MemoryExtractionSourceType =
  typeof MemorySourceTypes.Conversation;
export type MemoryCandidateStatus = typeof MemoryStatuses.Candidate;
export type MemoryExtractionMessage = Pick<
  ConversationMessage,
  "role" | "content" | "timestamp"
>;

export interface MemoryExtractionRequest {
  lifeId: string;
  messages: readonly MemoryExtractionMessage[];
  sourceType: MemoryExtractionSourceType;
}

export interface MemoryCandidate {
  lifeId: string;
  kind: MemoryKind;
  status: MemoryCandidateStatus;
  content: string;
  summary: string;
  importance: number;
  confidence: number;
  sourceType: MemoryExtractionSourceType;
  sourceCreatedAt: string;
  isSensitive: boolean;
}

export interface MemoryExtractionResult {
  lifeId: string;
  sourceType: MemoryExtractionSourceType;
  candidates: readonly MemoryCandidate[];
  analyzedMessageCount: number;
  rejectedSensitiveCount: number;
}
