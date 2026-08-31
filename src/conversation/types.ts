import type { ConversationMemoryMetadata, GovernedConversationResponse } from "../model";

export type ConversationMessageRole = "user" | "assistant";

export interface ConversationMessage {
  role: ConversationMessageRole;
  content: string;
  timestamp: string;
  sequenceNo?: number;
}

export interface ConversationRequest {
  userInput: string;
  perceptionAttachmentId?: string;
}

export interface ConversationResponse {
  sessionId: string;
  userMessage: ConversationMessage;
  assistantMessage: ConversationMessage;
  runtime: GovernedConversationResponse;
  memory: ConversationMemoryMetadata;
}
