import type { ModelConfig, ModelResponse } from "../model";
import type { PromptCompilerVersion } from "../prompt";

export type ConversationMessageRole = "user" | "assistant" | "system";

export interface ConversationMessage {
  role: ConversationMessageRole;
  content: string;
  timestamp: string;
}

export interface ConversationRequest {
  userInput: string;
  modelConfig: ModelConfig;
  temperature: number;
  maxTokens: number;
}

export interface ConversationResponse {
  sessionId: string;
  lifeId: string;
  personaId: string;
  promptCompilerVersion: PromptCompilerVersion;
  userMessage: ConversationMessage;
  assistantMessage: ConversationMessage;
  modelResponse: ModelResponse;
}
