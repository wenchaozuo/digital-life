import { bodyStateMachine } from "../body";
import { lifeIdentityManager, type LifeIdentity } from "../life";
import {
  modelService,
  type GovernedConversationRequest,
  type GovernedConversationResponse,
} from "../model";
import { MemorySourceTypes, memoryExtractor, type MemoryExtractionResult } from "../memory";
import { ConversationSession } from "./session";
import type { ConversationMessage, ConversationRequest, ConversationResponse } from "./types";

export class ConversationError extends Error {
  constructor(readonly code: string, message: string, readonly recoverable: boolean) {
    super(message);
    this.name = "ConversationError";
  }
}

interface ConversationModelPort {
  chatWithGovernedContext(request: GovernedConversationRequest): Promise<GovernedConversationResponse>;
}
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
}

/** Frontend state coordinator. Rust owns identity, persona, memory, and prompt construction. */
export class ConversationService {
  private readonly dependencies: ConversationServiceDependencies;
  private isSending = false;

  constructor(dependencies: Partial<ConversationServiceDependencies> = {}) {
    this.dependencies = {
      model: dependencies.model ?? modelService,
      life: dependencies.life ?? lifeIdentityManager,
      body: dependencies.body ?? bodyStateMachine,
      session: dependencies.session ?? new ConversationSession(),
    };
  }

  getSession(): ConversationSession { return this.dependencies.session; }
  clearSession(): void { this.dependencies.session.clear(); }

  async extractMemoryCandidates(): Promise<MemoryExtractionResult> {
    const life = await this.requireCurrentLife();
    return memoryExtractor.extract({ lifeId: life.id, messages: this.dependencies.session.getMessages(), sourceType: MemorySourceTypes.Conversation });
  }

  async send(request: ConversationRequest): Promise<ConversationResponse> {
    const userInput = request.userInput.trim();
    if (!userInput) throw new ConversationError("CONVERSATION_INPUT_REQUIRED", "Enter a message before sending.", true);
    if (this.isSending) throw new ConversationError("CONVERSATION_IN_PROGRESS", "A conversation request is already in progress.", true);
    this.isSending = true;
    this.dependencies.body.transition("thinking");
    try {
      const history = this.dependencies.session.getMessages().map(({ role, content }) => ({ role, content }));
      const runtime = await this.dependencies.model.chatWithGovernedContext({
        requestId: crypto.randomUUID(), userMessage: userInput, history,
      });
      const timestamp = new Date().toISOString();
      const userMessage: ConversationMessage = { role: "user", content: userInput, timestamp };
      const assistantMessage: ConversationMessage = { role: "assistant", content: runtime.assistantMessage, timestamp: new Date().toISOString() };
      this.dependencies.session.appendTurn(userMessage, assistantMessage);
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

  private async requireCurrentLife(): Promise<LifeIdentity> {
    const life = await this.dependencies.life.getCurrent();
    if (!life) throw new ConversationError("CONVERSATION_LIFE_NOT_FOUND", "No current digital life is available for conversation.", false);
    return life;
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
