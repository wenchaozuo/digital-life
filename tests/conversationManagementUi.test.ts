import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { ConversationSession } from "../src/conversation/session/conversationSession.ts";
import type { PersistedConversationMessage } from "../src/model/modelService.ts";

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath: string) => fs.readFileSync(path.join(workspace, relativePath), "utf8");

const firstConversation: PersistedConversationMessage[] = [
  { role: "user", content: "first user", sequenceNo: 1, createdAt: "2026-07-13T00:00:01Z" },
  { role: "assistant", content: "first assistant", sequenceNo: 2, createdAt: "2026-07-13T00:00:02Z" },
];
const secondConversation: PersistedConversationMessage[] = [
  { role: "user", content: "second user", sequenceNo: 1, createdAt: "2026-07-13T01:00:01Z" },
  { role: "assistant", content: "second assistant", sequenceNo: 2, createdAt: "2026-07-13T01:00:02Z" },
];

test("first open has no implicit conversation creation", () => {
  const source = read("src/conversation/conversationService.ts");
  const initialize = source.match(/async initialize\(\): Promise<void> \{[\s\S]*?\n  \}/)?.[0];
  assert.ok(initialize);
  assert.match(initialize, /conversations\.length === 0/);
  assert.match(initialize, /currentConversation = undefined/);
  assert.doesNotMatch(initialize, /history\.create/);
});

test("sidebar renders backend order directly and exposes persisted title and update time", () => {
  const source = read("src/chat/ConversationSidebar.vue");
  assert.match(source, /v-for="conversation in conversations"/);
  assert.match(source, /conversation\.title/);
  assert.match(source, /conversation\.updatedAt/);
  assert.doesNotMatch(source, /conversations\.sort/);
});

test("creating a conversation changes selection and clears only display cache", () => {
  const source = read("src/conversation/conversationService.ts");
  const create = source.match(/async createConversation\(title = "新对话"\): Promise<ConversationSummary> \{[\s\S]*?\n  \}/)?.[0];
  assert.ok(create);
  assert.match(create, /history\.create\(title\)/);
  assert.match(create, /session\.switchConversation\(\)/);
  assert.match(create, /currentConversation = conversation/);
  assert.doesNotMatch(create, /chatWithGovernedContext/);
});

test("switching replaces the display cache without leaking messages across conversations", () => {
  const session = new ConversationSession(20, "session", "2026-07-13T00:00:00Z");
  session.replaceMessagesFromPersistence(firstConversation);
  session.switchConversation();
  session.replaceMessagesFromPersistence(secondConversation);
  assert.deepEqual(session.getMessages().map((message) => message.content), ["second user", "second assistant"]);

  const source = read("src/conversation/conversationService.ts");
  const restore = source.match(/private async restoreConversation\(conversation: ConversationSummary\): Promise<void> \{[\s\S]*?\n  \}/)?.[0];
  assert.ok(restore);
  assert.ok(restore.indexOf("history.getMessages") < restore.indexOf("session.switchConversation"));
  assert.ok(restore.indexOf("session.switchConversation") < restore.indexOf("currentConversation = conversation"));
});

test("delete confirms in the UI and leaves no selected display session after success", () => {
  const view = read("src/chat/ChatView.vue");
  assert.match(view, /window\.confirm\(/);
  assert.match(view, /conversationService\.deleteCurrentConversation\(\)/);
  assert.match(view, /clearSignal\.value \+= 1/);

  const service = read("src/conversation/conversationService.ts");
  const deletion = service.match(/async deleteCurrentConversation\(\): Promise<void> \{[\s\S]*?\n  \}/)?.[0];
  assert.ok(deletion);
  assert.match(deletion, /currentConversation = undefined/);
  assert.match(deletion, /session\.switchConversation\(\)/);
});

test("chat capability exposes governed chat and conversation management, but no profile, secret, or vector worker commands", () => {
  const permission = read("src-tauri/permissions/chat-commands.toml");
  for (const command of [
    "chat_with_governed_context",
    "create_conversation",
    "list_conversations",
    "get_conversation_messages",
    "rename_conversation",
    "delete_conversation",
  ]) {
    assert.match(permission, new RegExp(`"${command}"`));
  }
  assert.doesNotMatch(permission, /model_profile|api_credential|vector_index|vector_sync/);
});

test("failed chat requests cannot append to the frontend session cache", () => {
  const source = read("src/conversation/conversationService.ts");
  const append = source.indexOf("this.dependencies.session.appendPersistedTurn");
  const catchBlock = source.indexOf("} catch (caught) {");
  assert.ok(append >= 0 && catchBlock > append);
  assert.doesNotMatch(source.slice(catchBlock), /appendPersistedTurn/);
});
