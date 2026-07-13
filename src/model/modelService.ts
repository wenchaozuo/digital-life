import { invoke } from "@tauri-apps/api/core";

export interface GovernedConversationMessage {
  role: "user" | "assistant";
  content: string;
}

export interface GovernedConversationRequest {
  requestId: string;
  userMessage: string;
  history: GovernedConversationMessage[];
}

export type ConversationDegradationCode =
  | "VECTOR_SKIPPED_SENSITIVE_QUERY"
  | "NO_ACTIVE_EMBEDDING_PROFILE"
  | "EMBEDDING_CREDENTIAL_NOT_FOUND"
  | "EMBEDDING_PROVIDER_UNAVAILABLE"
  | "INDEX_DIRECTORY_MISSING"
  | "VECTOR_STORE_UNAVAILABLE"
  | "VECTOR_INDEX_UNAVAILABLE"
  | "VECTOR_UNAVAILABLE"
  | "KEYWORD_UNAVAILABLE"
  | "BOTH_RETRIEVAL_UNAVAILABLE"
  | "AUTHORITATIVE_READ_UNAVAILABLE"
  | "MEMORY_CONTEXT_UNAVAILABLE";

export interface ConversationMemoryMetadata {
  retrievedCount: number;
  usedCount: number;
  truncated: boolean;
  degradationCodes: ConversationDegradationCode[];
  vectorAvailability: "HYBRID" | "KEYWORD_ONLY" | "VECTOR_ONLY" | "NO_MEMORY";
  rebuildRecommended: boolean;
}

export interface GovernedConversationResponse {
  requestId: string;
  assistantMessage: string;
  profileDisplayName: string;
  modelName: string;
  memory: ConversationMemoryMetadata;
  latencyMs: number;
}

export class ModelService {
  async chatWithGovernedContext(
    request: GovernedConversationRequest,
  ): Promise<GovernedConversationResponse> {
    return invoke<GovernedConversationResponse>("chat_with_governed_context", { request });
  }
}

export const modelService = new ModelService();
