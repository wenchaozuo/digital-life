import type { ModelResponse } from "../model";
import type { PromptCompilerVersion } from "../prompt";
import type { ConversationMemoryWarning } from "./memoryContextIntegration";

export type ConversationMessageRole = "user" | "assistant" | "system";

export interface ConversationMessage {
  role: ConversationMessageRole;
  content: string;
  timestamp: string;
}

export interface ConversationRequest {
  userInput: string;
}

export interface ConversationResponse {
  sessionId: string;
  lifeId: string;
  personaId: string;
  promptCompilerVersion: PromptCompilerVersion;
  userMessage: ConversationMessage;
  assistantMessage: ConversationMessage;
  modelResponse: ModelResponse;
  retrievedMemoryCount?: number;
  usedMemoryCount?: number;
  usedMemoryIds?: readonly string[];
  memoryContextTruncated?: boolean;
  memoryWarning?: ConversationMemoryWarning;
}
