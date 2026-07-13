import { invoke } from "@tauri-apps/api/core";
import type { PersistedConversationMessage } from "../model";

export interface ConversationSummary {
  id: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  lastMessageAt: string;
}

export interface DeleteConversationResult {
  conversationId: string;
  deleted: boolean;
}

export interface ConversationHistoryPort {
  create(title: string): Promise<ConversationSummary>;
  list(): Promise<ConversationSummary[]>;
  getMessages(conversationId: string): Promise<PersistedConversationMessage[]>;
  rename(conversationId: string, title: string): Promise<ConversationSummary>;
  delete(conversationId: string): Promise<DeleteConversationResult>;
}

export class ConversationHistoryService implements ConversationHistoryPort {
  create(title: string): Promise<ConversationSummary> {
    return invoke<ConversationSummary>("create_conversation", {
      request: { title },
    });
  }

  list(): Promise<ConversationSummary[]> {
    return invoke<ConversationSummary[]>("list_conversations");
  }

  getMessages(conversationId: string): Promise<PersistedConversationMessage[]> {
    return invoke<PersistedConversationMessage[]>("get_conversation_messages", {
      request: { conversationId },
    });
  }

  rename(conversationId: string, title: string): Promise<ConversationSummary> {
    return invoke<ConversationSummary>("rename_conversation", {
      request: { conversationId, title },
    });
  }

  delete(conversationId: string): Promise<DeleteConversationResult> {
    return invoke<DeleteConversationResult>("delete_conversation", {
      request: { conversationId },
    });
  }
}

export const conversationHistoryService = new ConversationHistoryService();
