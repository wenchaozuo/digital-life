import { bodyStateMachine } from "../body";
import { lifeIdentityManager, type LifeIdentity } from "../life";
import {
  modelService,
  type GovernedConversationRequest,
  type GovernedConversationResponse,
} from "../model";
import { MemorySourceTypes, memoryExtractor, type MemoryExtractionResult } from "../memory";
import {
  conversationHistoryService,
  type ConversationHistoryPort,
  type ConversationSummary,
} from "./conversationHistoryService";
import { ConversationSession } from "./session";
import type { ConversationMessage, ConversationRequest, ConversationResponse } from "./types";

export class ConversationError extends Error {
  readonly code: string;
  readonly recoverable: boolean;

  constructor(code: string, message: string, recoverable: boolean) {
    super(message);
    this.name = "ConversationError";
    this.code = code;
    this.recoverable = recoverable;
  }
}

interface ConversationModelPort {
  chatWithGovernedContext(request: GovernedConversationRequest): Promise<GovernedConversationResponse>;
}

interface PendingPerceptionRetry {
  requestId: string;
  conversationId: string;
  currentMessage: string;
  perceptionAttachmentId: string;
}

const PERCEPTION_CONTEXT_RETRY_MISMATCH_CODE = "PERCEPTION_CONTEXT_RETRY_MISMATCH";
const PERCEPTION_CONTEXT_RETRY_MISMATCH_MESSAGE =
  "This attached screen context is reserved for the previous failed message. Retry that message unchanged or observe and attach the screen again.";

interface ConversationLifePort { getCurrent(): Promise<LifeIdentity | undefined>; }
interface ConversationBodyPort {
  transition(state: "thinking" | "speaking" | "idle" | "error"): unknown;
  getState(): string;
}
export interface ConversationServiceDependencies {
  model: ConversationModelPort;
  life: ConversationLifePort;
  body: ConversationBodyPort;
  session: ConversationSession;
  history: ConversationHistoryPort;
}

/** Frontend state coordinator. Rust owns identity, persona, memory, and prompt construction. */
export class ConversationService {
  private readonly dependencies: ConversationServiceDependencies;
  private isSending = false;
  private isDeleting = false;
  private isRestoring = false;
  private currentConversation?: ConversationSummary;
  private pendingPerceptionRetry?: PendingPerceptionRetry;

  constructor(dependencies: Partial<ConversationServiceDependencies> = {}) {
    this.dependencies = {
      model: dependencies.model ?? modelService,
      life: dependencies.life ?? lifeIdentityManager,
      body: dependencies.body ?? bodyStateMachine,
      session: dependencies.session ?? new ConversationSession(),
      history: dependencies.history ?? conversationHistoryService,
    };
  }

  getSession(): ConversationSession { return this.dependencies.session; }
  getConversationId(): string | undefined { return this.currentConversation?.id; }
  getConversationTitle(): string | undefined { return this.currentConversation?.title; }

  /** Preserves SQLite's authoritative, already-sorted conversation order. */
  listConversations(): Promise<ConversationSummary[]> {
    return this.dependencies.history.list();
  }

  async createConversation(title = "新对话"): Promise<ConversationSummary> {
    if (this.isSending || this.isDeleting || this.isRestoring) {
      throw new ConversationError("CONVERSATION_IN_PROGRESS", "The current conversation is busy.", true);
    }
    this.isRestoring = true;
    try {
      const conversation = await this.dependencies.history.create(title);
      this.dependencies.session.switchConversation();
      this.currentConversation = conversation;
      return conversation;
    } finally {
      this.isRestoring = false;
    }
  }

  async initialize(): Promise<void> {
    if (this.isSending || this.isDeleting || this.isRestoring) return;
    this.isRestoring = true;
    try {
      const conversations = await this.dependencies.history.list();
      if (conversations.length === 0) {
        this.currentConversation = undefined;
        this.dependencies.session.switchConversation();
        return;
      }
      await this.restoreConversation(conversations[0]);
    } finally {
      this.isRestoring = false;
    }
  }

  async switchConversation(conversation: ConversationSummary): Promise<void> {
    if (this.isSending || this.isDeleting || this.isRestoring) {
      throw new ConversationError("CONVERSATION_IN_PROGRESS", "The current conversation is busy.", true);
    }
    this.isRestoring = true;
    try {
      await this.restoreConversation(conversation);
    } finally {
      this.isRestoring = false;
    }
  }

  async renameCurrentConversation(title: string): Promise<void> {
    const conversationId = this.currentConversation?.id;
    if (!conversationId) throw new ConversationError("CONVERSATION_NOT_FOUND", "No conversation is selected.", true);
    this.currentConversation = await this.dependencies.history.rename(conversationId, title);
  }

  async deleteCurrentConversation(): Promise<void> {
    const conversationId = this.currentConversation?.id;
    if (!conversationId) return;
    if (this.isSending || this.isDeleting || this.isRestoring) {
      throw new ConversationError("CONVERSATION_IN_PROGRESS", "The current conversation is busy.", true);
    }
    this.isDeleting = true;
    try {
      await this.dependencies.history.delete(conversationId);
      this.currentConversation = undefined;
      this.dependencies.session.switchConversation();
    } finally {
      this.isDeleting = false;
    }
  }

  async extractMemoryCandidates(): Promise<MemoryExtractionResult> {
    const life = await this.requireCurrentLife();
    return memoryExtractor.extract({ lifeId: life.id, messages: this.dependencies.session.getMessages(), sourceType: MemorySourceTypes.Conversation });
  }

  async send(request: ConversationRequest): Promise<ConversationResponse> {
    const userInput = request.userInput.trim();
    if (!userInput) throw new ConversationError("CONVERSATION_INPUT_REQUIRED", "Enter a message before sending.", true);
    if (this.isSending || this.isRestoring) throw new ConversationError("CONVERSATION_IN_PROGRESS", "A conversation request is already in progress.", true);
    if (this.isDeleting) throw new ConversationError("CONVERSATION_IN_PROGRESS", "The conversation is being deleted.", true);
    this.isSending = true;
    this.dependencies.body.transition("thinking");
    try {
      if (!this.currentConversation) {
        this.currentConversation = await this.dependencies.history.create("新对话");
      }
      const perceptionAttachmentId = request.perceptionAttachmentId;
      const pendingPerceptionRetry = perceptionAttachmentId === undefined
        ? undefined
        : this.establishPerceptionRetry(
          this.currentConversation.id,
          userInput,
          perceptionAttachmentId,
        );
      const requestId = pendingPerceptionRetry?.requestId ?? crypto.randomUUID();
      const governedRequest: GovernedConversationRequest = {
        requestId,
        conversationId: this.currentConversation.id,
        currentMessage: userInput,
        ...(perceptionAttachmentId === undefined ? {} : { perceptionAttachmentId }),
      };
      const runtime = await this.dependencies.model.chatWithGovernedContext({
        ...governedRequest,
      });
      if (pendingPerceptionRetry !== undefined) {
        this.clearMatchingPerceptionRetry(pendingPerceptionRetry);
      }
      this.dependencies.session.appendPersistedTurn(runtime.persistedMessages);
      const [userMessage, assistantMessage] = runtime.persistedMessages.map((message) => ({
        role: message.role,
        content: message.content,
        timestamp: message.createdAt,
        sequenceNo: message.sequenceNo,
      })) as [ConversationMessage, ConversationMessage];
      this.dependencies.body.transition("speaking");
      return { sessionId: this.dependencies.session.sessionId, userMessage, assistantMessage, runtime, memory: runtime.memory };
    } catch (caught) {
      this.dependencies.body.transition("error");
      throw toConversationError(caught);
    } finally {
      if (this.dependencies.body.getState() === "speaking") this.dependencies.body.transition("idle");
      this.isSending = false;
    }
  }

  private establishPerceptionRetry(
    conversationId: string,
    currentMessage: string,
    perceptionAttachmentId: string,
  ): PendingPerceptionRetry {
    const existing = this.pendingPerceptionRetry;
    if (existing?.perceptionAttachmentId === perceptionAttachmentId) {
      if (
        existing.conversationId !== conversationId
        || existing.currentMessage !== currentMessage
      ) {
        throw new ConversationError(
          PERCEPTION_CONTEXT_RETRY_MISMATCH_CODE,
          PERCEPTION_CONTEXT_RETRY_MISMATCH_MESSAGE,
          true,
        );
      }
      return existing;
    }

    const next: PendingPerceptionRetry = {
      requestId: crypto.randomUUID(),
      conversationId,
      currentMessage,
      perceptionAttachmentId,
    };
    this.pendingPerceptionRetry = next;
    return next;
  }

  private clearMatchingPerceptionRetry(retry: PendingPerceptionRetry): void {
    const current = this.pendingPerceptionRetry;
    if (
      current?.requestId === retry.requestId
      && current.conversationId === retry.conversationId
      && current.currentMessage === retry.currentMessage
      && current.perceptionAttachmentId === retry.perceptionAttachmentId
    ) {
      this.pendingPerceptionRetry = undefined;
    }
  }

  private async requireCurrentLife(): Promise<LifeIdentity> {
    const life = await this.dependencies.life.getCurrent();
    if (!life) throw new ConversationError("CONVERSATION_LIFE_NOT_FOUND", "No current digital life is available for conversation.", false);
    return life;
  }

  private async restoreConversation(conversation: ConversationSummary): Promise<void> {
    const messages = await this.dependencies.history.getMessages(conversation.id);
    this.dependencies.session.switchConversation();
    this.currentConversation = conversation;
    this.dependencies.session.replaceMessagesFromPersistence(messages);
  }
}

function toConversationError(error: unknown): ConversationError {
  if (error instanceof ConversationError) return error;
  if (typeof error === "object" && error !== null) {
    const value = error as { code?: unknown; message?: unknown; recoverable?: unknown };
    if (typeof value.code === "string" && typeof value.message === "string" && typeof value.recoverable === "boolean") {
      return new ConversationError(value.code, value.message, value.recoverable);
    }
  }
  return new ConversationError("CONVERSATION_MODEL_FAILED", "The model request could not be completed. No conversation data was saved.", true);
}

export const conversationService = new ConversationService();
