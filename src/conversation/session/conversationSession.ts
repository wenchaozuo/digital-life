import type { ConversationMessage } from "../types";

export const DEFAULT_SESSION_MESSAGE_LIMIT = 20;

export class ConversationSession {
  readonly sessionId: string;
  readonly createdAt: string;
  private messageHistory: ConversationMessage[] = [];
  private activityAt: string;

  constructor(
    private readonly messageLimit = DEFAULT_SESSION_MESSAGE_LIMIT,
    sessionId = crypto.randomUUID(),
    createdAt = new Date().toISOString(),
  ) {
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
  }

  getMessages(): readonly ConversationMessage[] {
    return this.messageHistory.map((message) => ({ ...message }));
  }

  clear(): void {
    this.messageHistory = [];
    this.activityAt = new Date().toISOString();
  }
}
