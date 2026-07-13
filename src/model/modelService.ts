import { invoke } from "@tauri-apps/api/core";

export type ModelMessageRole = "user" | "assistant" | "system";

export interface ModelMessage {
  role: ModelMessageRole;
  content: string;
}

export interface ModelRequest {
  messages: ModelMessage[];
  systemContext: string | null;
}

export interface ModelUsage {
  inputTokens: number;
  outputTokens: number;
  totalTokens: number;
}

export type ModelFinishReason =
  | "stop"
  | "length"
  | "contentFilter"
  | "toolCalls"
  | "other";

export interface ModelResponse {
  text: string;
  modelName: string;
  usage: ModelUsage;
  finishReason: ModelFinishReason;
}

export interface ModelError {
  code: string;
  message: string;
  recoverable: boolean;
}

export const MODEL_STREAM_EVENT_NAME = "model:stream" as const;

export type ModelStreamEventKind =
  | { type: "started"; modelName: string }
  | { type: "delta"; text: string }
  | { type: "completed"; response: ModelResponse }
  | { type: "failed"; error: ModelError };

export interface ModelStreamEvent {
  requestId: string;
  event: ModelStreamEventKind;
}

export class ModelService {
  async chat(request: ModelRequest): Promise<ModelResponse> {
    return invoke<ModelResponse>("chat_with_active_model", { request });
  }
}

export const modelService = new ModelService();
