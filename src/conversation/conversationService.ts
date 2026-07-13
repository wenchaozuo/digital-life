import { bodyStateMachine } from "../body";
import { lifeIdentityManager, type LifeIdentity } from "../life";
import { modelService, type ModelRequest, type ModelResponse } from "../model";
import {
  MemorySourceTypes,
  memoryExtractor,
  memoryRetrieverService,
  type MemoryExtractionResult,
} from "../memory";
import { personaManager, type PersonaTemplate } from "../persona";
import { PromptCompiler } from "../prompt";
import {
  combineConversationSystemContext,
  prepareConversationMemoryContext,
  type MemoryRetrieverPort,
} from "./memoryContextIntegration";
import { ConversationSession } from "./session";
import type {
  ConversationMessage,
  ConversationRequest,
  ConversationResponse,
} from "./types";

export class ConversationError extends Error {
  readonly code: string;
  readonly recoverable: boolean;

  constructor(
    code: string,
    message: string,
    recoverable: boolean,
  ) {
    super(message);
    this.name = "ConversationError";
    this.code = code;
    this.recoverable = recoverable;
  }
}

interface ConversationModelPort {
  chat(request: ModelRequest): Promise<ModelResponse>;
}

interface ConversationLifePort {
  getCurrent(): Promise<LifeIdentity | undefined>;
}

interface ConversationPersonaPort {
  getById(id: string): Promise<PersonaTemplate | undefined>;
}

interface ConversationBodyPort {
  transition(state: "thinking" | "speaking" | "idle" | "error"): unknown;
  getState(): string;
}

export interface ConversationServiceDependencies {
  model: ConversationModelPort;
  life: ConversationLifePort;
  persona: ConversationPersonaPort;
  memory: MemoryRetrieverPort;
  body: ConversationBodyPort;
  session: ConversationSession;
}

export class ConversationService {
  private readonly promptCompiler = new PromptCompiler();
  private readonly dependencies: ConversationServiceDependencies;
  private isSending = false;

  constructor(
    dependencies: Partial<ConversationServiceDependencies> = {},
  ) {
    this.dependencies = {
      model: dependencies.model ?? modelService,
      life: dependencies.life ?? lifeIdentityManager,
      persona: dependencies.persona ?? personaManager,
      memory: dependencies.memory ?? memoryRetrieverService,
      body: dependencies.body ?? bodyStateMachine,
      session: dependencies.session ?? new ConversationSession(),
    };
  }

  getSession(): ConversationSession {
    return this.dependencies.session;
  }

  clearSession(): void {
    this.dependencies.session.clear();
  }

  async extractMemoryCandidates(): Promise<MemoryExtractionResult> {
    const life = await this.requireCurrentLife();
    return memoryExtractor.extract({
      lifeId: life.id,
      messages: this.dependencies.session.getMessages(),
      sourceType: MemorySourceTypes.Conversation,
    });
  }

  async send(request: ConversationRequest): Promise<ConversationResponse> {
    const userInput = request.userInput.trim();
    if (userInput.length === 0) {
      throw new ConversationError(
        "CONVERSATION_INPUT_REQUIRED",
        "Enter a message before sending.",
        true,
      );
    }

    if (this.isSending) {
      throw new ConversationError(
        "CONVERSATION_IN_PROGRESS",
        "A conversation request is already in progress.",
        true,
      );
    }

    this.isSending = true;
    this.dependencies.body.transition("thinking");

    try {
      const life = await this.requireCurrentLife();
      const persona = await this.requirePersona(life);
      const compilation = this.promptCompiler.compile(persona);
      const memoryPreparation = await prepareConversationMemoryContext(
        life.id,
        userInput,
        this.dependencies.memory,
      );
      const systemContext = combineConversationSystemContext(
        compilation.systemContext,
        memoryPreparation.memoryContext,
      );
      const userMessage: ConversationMessage = {
        role: "user",
        content: userInput,
        timestamp: new Date().toISOString(),
      };
      const history = this.dependencies.session.getMessages();
      this.dependencies.session.addMessage(userMessage);
      const modelRequest: ModelRequest = {
        messages: [...history, userMessage].map(({ role, content }) => ({
          role,
          content,
        })),
        systemContext,
      };
      const modelResponse = await this.dependencies.model.chat(modelRequest);
      const assistantMessage: ConversationMessage = {
        role: "assistant",
        content: modelResponse.text,
        timestamp: new Date().toISOString(),
      };
      this.dependencies.session.addMessage(assistantMessage);

      this.dependencies.body.transition("speaking");
      return {
        sessionId: this.dependencies.session.sessionId,
        lifeId: life.id,
        personaId: persona.id,
        promptCompilerVersion: compilation.compilerVersion,
        userMessage,
        assistantMessage,
        modelResponse,
        retrievedMemoryCount:
          memoryPreparation.memoryContext.retrievedCount,
        usedMemoryCount: memoryPreparation.memoryContext.usedCount,
        usedMemoryIds: memoryPreparation.memoryContext.usedMemoryIds,
        memoryContextTruncated: memoryPreparation.memoryContext.truncated,
        memoryWarning: memoryPreparation.warning,
      };
    } catch (error) {
      this.dependencies.body.transition("error");
      throw toConversationError(error);
    } finally {
      if (this.dependencies.body.getState() === "speaking") {
        this.dependencies.body.transition("idle");
      }
      this.isSending = false;
    }
  }

  private async requireCurrentLife(): Promise<LifeIdentity> {
    const life = await this.dependencies.life.getCurrent();
    if (!life) {
      throw new ConversationError(
        "CONVERSATION_LIFE_NOT_FOUND",
        "No current digital life is available for conversation.",
        false,
      );
    }

    return life;
  }

  private async requirePersona(life: LifeIdentity): Promise<PersonaTemplate> {
    const persona = await this.dependencies.persona.getById(life.personaId);
    if (!persona) {
      throw new ConversationError(
        "CONVERSATION_PERSONA_NOT_FOUND",
        "The current digital life's persona template could not be loaded.",
        false,
      );
    }

    return persona;
  }
}

function toConversationError(error: unknown): ConversationError {
  if (error instanceof ConversationError) {
    return error;
  }

  if (isStructuredError(error)) {
    return new ConversationError(error.code, error.message, error.recoverable);
  }

  return new ConversationError(
    "CONVERSATION_MODEL_FAILED",
    "The model request could not be completed. No conversation data was saved.",
    true,
  );
}

function isStructuredError(
  error: unknown,
): error is { code: string; message: string; recoverable: boolean } {
  if (typeof error !== "object" || error === null) {
    return false;
  }

  const candidate = error as Record<string, unknown>;
  return (
    typeof candidate.code === "string" &&
    typeof candidate.message === "string" &&
    typeof candidate.recoverable === "boolean"
  );
}

export const conversationService = new ConversationService();
