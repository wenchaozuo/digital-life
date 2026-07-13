import type { ConversationMessage } from "../types";
import type { PersistedConversationMessage } from "../../model";

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

  replaceMessagesFromPersistence(messages: readonly PersistedConversationMessage[]): void {
    this.messageHistory = messages
      .map(toDisplayMessage)
      .sort((left, right) => (left.sequenceNo ?? 0) - (right.sequenceNo ?? 0))
      .slice(-this.messageLimit);
    this.activityAt = this.messageHistory[this.messageHistory.length - 1]?.timestamp ?? new Date().toISOString();
    this.notifyListeners();
  }

  appendPersistedTurn(messages: readonly PersistedConversationMessage[]): void {
    if (
      messages.length !== 2
      || messages[0].role !== "user"
      || messages[1].role !== "assistant"
      || messages[1].sequenceNo !== messages[0].sequenceNo + 1
    ) {
      throw new Error("A persisted conversation turn must contain one complete ordered turn.");
    }
    const sequences = new Set(messages.map((message) => message.sequenceNo));
    this.messageHistory = this.messageHistory
      .filter((message) => message.sequenceNo === undefined || !sequences.has(message.sequenceNo))
      .concat(messages.map(toDisplayMessage))
      .sort((left, right) => (left.sequenceNo ?? 0) - (right.sequenceNo ?? 0))
      .slice(-this.messageLimit);
    this.activityAt = messages[1].createdAt;
    this.notifyListeners();
  }

  getMessages(): readonly ConversationMessage[] {
    return this.messageHistory.map((message) => ({ ...message }));
  }

  clearForConversationSwitch(): void {
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

function toDisplayMessage(message: PersistedConversationMessage): ConversationMessage {
  return {
    role: message.role,
    content: message.content,
    timestamp: message.createdAt,
    sequenceNo: message.sequenceNo,
  };
}
