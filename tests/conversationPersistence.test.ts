import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { ConversationSession } from "../src/conversation/session/conversationSession.ts";
import type { PersistedConversationMessage } from "../src/model/modelService.ts";

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath: string) => fs.readFileSync(path.join(workspace, relativePath), "utf8");
const persisted: PersistedConversationMessage[] = [
  { role: "user", content: "stored user", sequenceNo: 1, createdAt: "2026-07-13T00:00:01Z" },
  { role: "assistant", content: "stored assistant", sequenceNo: 2, createdAt: "2026-07-13T00:00:02Z" },
];

test("session replaces, deduplicates, and clears persisted display messages", () => {
  const session = new ConversationSession(20, "session", "2026-07-13T00:00:00Z");
  session.replaceMessagesFromPersistence([...persisted].reverse());
  assert.deepEqual(session.getMessages().map((message) => message.sequenceNo), [1, 2]);
  session.appendPersistedTurn(persisted);
  assert.equal(session.getMessages().length, 2);
  session.clearForConversationSwitch();
  assert.deepEqual(session.getMessages(), []);
});

test("initialization restores the newest conversation and never creates an empty record", () => {
  const source = read("src/conversation/conversationService.ts");
  const initialize = source.match(/async initialize\(\): Promise<void> \{[\s\S]*?\n  \}/)?.[0];
  assert.ok(initialize);
  assert.match(initialize, /history\.list\(\)/);
  assert.match(initialize, /restoreConversation\(conversations\[0\]\)/);
  assert.doesNotMatch(initialize, /history\.create/);
  assert.match(source, /history\.getMessages\(conversation\.id\)/);
  assert.match(source, /replaceMessagesFromPersistence\(messages\)/);
});

test("first send creates once and submits no frontend history", () => {
  const source = read("src/conversation/conversationService.ts");
  const send = source.match(/async send\(request: ConversationRequest\): Promise<ConversationResponse> \{[\s\S]*?\n  \}/)?.[0];
  assert.ok(send);
  assert.match(send, /if \(!this\.currentConversation\)/);
  assert.match(send, /history\.create\("新对话"\)/);
  assert.match(send, /conversationId: this\.currentConversation\.id/);
  assert.match(send, /currentMessage: userInput/);
  assert.doesNotMatch(send, /history:/);
  const modelCall = send.indexOf("chatWithGovernedContext");
  const displayCommit = send.indexOf("appendPersistedTurn");
  assert.ok(modelCall >= 0 && displayCommit > modelCall);
});

test("failure cannot update display history and deletion clears selected conversation", () => {
  const source = read("src/conversation/conversationService.ts");
  const append = source.indexOf("this.dependencies.session.appendPersistedTurn");
  const catchBlock = source.indexOf("} catch (caught) {");
  assert.ok(append >= 0 && catchBlock > append);
  assert.doesNotMatch(source.slice(catchBlock), /appendPersistedTurn/);
  const deletion = source.match(/async deleteCurrentConversation\(\): Promise<void> \{[\s\S]*?\n  \}/)?.[0];
  assert.ok(deletion);
  assert.match(deletion, /await this\.dependencies\.history\.delete\(conversationId\)/);
  assert.match(deletion, /this\.currentConversation = undefined/);
  assert.match(deletion, /clearForConversationSwitch\(\)/);
});
