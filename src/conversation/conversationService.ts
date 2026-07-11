import { bodyStateMachine } from "../body";
import { lifeIdentityManager, type LifeIdentity } from "../life";
import { modelService, type ModelRequest } from "../model";
import { personaManager, type PersonaTemplate } from "../persona";
import { PromptCompiler } from "../prompt";
import { ConversationSession } from "./session";
import type {
  ConversationMessage,
  ConversationRequest,
  ConversationResponse,
} from "./types";

export class ConversationError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly recoverable: boolean,
  ) {
    super(message);
    this.name = "ConversationError";
  }
}

export class ConversationService {
  private readonly promptCompiler = new PromptCompiler();
  private readonly session = new ConversationSession();
  private isSending = false;

  getSession(): ConversationSession {
    return this.session;
  }

  clearSession(): void {
    this.session.clear();
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
    bodyStateMachine.transition("thinking");

    try {
      const life = await this.requireCurrentLife();
      const persona = await this.requirePersona(life);
      const compilation = this.promptCompiler.compile(persona);
      const userMessage: ConversationMessage = {
        role: "user",
        content: userInput,
        timestamp: new Date().toISOString(),
      };
      const history = this.session.getMessages();
      this.session.addMessage(userMessage);
      const modelRequest: ModelRequest = {
        messages: [...history, userMessage].map(({ role, content }) => ({
          role,
          content,
        })),
        systemContext: compilation.systemContext,
        temperature: request.temperature,
        maxTokens: request.maxTokens,
      };
      const modelResponse = await modelService.chat(request.modelConfig, modelRequest);
      const assistantMessage: ConversationMessage = {
        role: "assistant",
        content: modelResponse.text,
        timestamp: new Date().toISOString(),
      };
      this.session.addMessage(assistantMessage);

      bodyStateMachine.transition("speaking");
      return {
        sessionId: this.session.sessionId,
        lifeId: life.id,
        personaId: persona.id,
        promptCompilerVersion: compilation.compilerVersion,
        userMessage,
        assistantMessage,
        modelResponse,
      };
    } catch (error) {
      bodyStateMachine.transition("error");
      throw toConversationError(error);
    } finally {
      if (bodyStateMachine.getState() === "speaking") {
        bodyStateMachine.transition("idle");
      }
      this.isSending = false;
    }
  }

  private async requireCurrentLife(): Promise<LifeIdentity> {
    const life = await lifeIdentityManager.getCurrent();
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
    const persona = await personaManager.getById(life.personaId);
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
