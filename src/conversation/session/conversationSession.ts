import type { ConversationMessage } from "../types";

export const DEFAULT_SESSION_MESSAGE_LIMIT = 20;

type ConversationSessionListener = () => void;

export class ConversationSession {
  readonly sessionId: string;
  readonly createdAt: string;
  private readonly messageLimit: number;
  private messageHistory: ConversationMessage[] = [];
  private activityAt: string;
  private readonly listeners = new Set<ConversationSessionListener>();

  constructor(
    messageLimit = DEFAULT_SESSION_MESSAGE_LIMIT,
    sessionId = crypto.randomUUID(),
    createdAt = new Date().toISOString(),
  ) {
    this.messageLimit = messageLimit;
    this.sessionId = sessionId;
    this.createdAt = createdAt;
    this.activityAt = createdAt;
  }

  get messages(): readonly ConversationMessage[] {
    return this.getMessages();
  }

  get lastActivity(): string {
    return this.activityAt;
  }

  addMessage(message: ConversationMessage): void {
    this.messageHistory.push({ ...message });
    if (this.messageHistory.length > this.messageLimit) {
      this.messageHistory.splice(0, this.messageHistory.length - this.messageLimit);
    }
    this.activityAt = message.timestamp;
    this.notifyListeners();
  }

  /** Atomically commits a completed user/assistant turn. */
  appendTurn(userMessage: ConversationMessage, assistantMessage: ConversationMessage): void {
    if (userMessage.role !== "user" || assistantMessage.role !== "assistant") {
      throw new Error("A conversation turn must contain one user and one assistant message.");
    }
    this.messageHistory.push({ ...userMessage }, { ...assistantMessage });
    if (this.messageHistory.length > this.messageLimit) {
      this.messageHistory.splice(0, this.messageHistory.length - this.messageLimit);
    }
    this.activityAt = assistantMessage.timestamp;
    this.notifyListeners();
  }

  getMessages(): readonly ConversationMessage[] {
    return this.messageHistory.map((message) => ({ ...message }));
  }

  clear(): void {
    this.messageHistory = [];
    this.activityAt = new Date().toISOString();
    this.notifyListeners();
  }

  subscribe(listener: ConversationSessionListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notifyListeners(): void {
    this.listeners.forEach((listener) => listener());
  }
}
