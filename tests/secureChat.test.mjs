import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => fs.readFileSync(path.join(workspace, relativePath), "utf8");

test("governed chat DTO contains only request id, conversation id, and current message", () => {
  const service = read("src/model/modelService.ts");
  const request = service.match(/export interface GovernedConversationRequest \{[\s\S]*?\n\}/)?.[0];
  assert.ok(request);
  assert.match(request, /requestId: string/);
  assert.match(request, /conversationId: string/);
  assert.match(request, /currentMessage: string/);
  assert.doesNotMatch(request, /history|userMessage|systemContext|persona|lifeIdentity|memory|apiKey|baseUrl|modelName|profileId|temperature|maxTokens/i);
});

test("frontend uses the governed IPC command without model overrides", () => {
  const service = read("src/model/modelService.ts");
  const method = service.match(/async chatWithGovernedContext\([\s\S]*?\n  \}/)?.[0];
  assert.ok(method);
  assert.match(method, /chat_with_governed_context/);
  assert.doesNotMatch(method, /apiKey|baseUrl|modelName|profileId|systemContext/);
});

test("conversation displays only backend-persisted turns after governed success", () => {
  const service = read("src/conversation/conversationService.ts");
  const session = read("src/conversation/session/conversationSession.ts");
  assert.match(service, /chatWithGovernedContext/);
  assert.match(service, /session\.appendPersistedTurn\(runtime\.persistedMessages\)/);
  assert.match(service, /transition\("thinking"\)/);
  assert.match(service, /transition\("speaking"\)/);
  assert.match(service, /transition\("error"\)/);
  assert.match(session, /appendPersistedTurn\(messages: readonly PersistedConversationMessage\[\]\)/);
  assert.match(session, /replaceMessagesFromPersistence/);
  assert.match(session, /clearForConversationSwitch/);
  assert.doesNotMatch(service, /getMessages\(\)\.map\(\(\{ role, content \}\)/);
  assert.doesNotMatch(service, /prepareConversationMemoryContext|promptCompiler|requirePersona/);
});

test("ChatView has no plaintext runtime model settings and retains failures for retry", () => {
  const view = read("src/chat/ChatView.vue");
  const input = read("src/chat/ChatInput.vue");
  assert.doesNotMatch(view, /apiKey|baseUrl|modelName|type="password"/i);
  assert.match(view, /memoryNotice/);
  assert.match(view, /clearSignal/);
  assert.match(input, /clearSignal/);
  assert.doesNotMatch(input, /content\.value = "";\s*}\s*$/m);
});

test("chat capability exposes only governed chat and no legacy cognition command", () => {
  const rust = read("src-tauri/src/lib.rs");
  const permission = read("src-tauri/permissions/chat-commands.toml");
  assert.match(rust, /conversation::service::chat_with_governed_context/);
  assert.match(permission, /"chat_with_governed_context"/);
  for (const command of [
    "create_conversation",
    "list_conversations",
    "get_conversation_messages",
    "rename_conversation",
    "delete_conversation",
  ]) assert.match(permission, new RegExp(`"${command}"`));
  assert.doesNotMatch(rust, /model::runtime::chat_with_active_model|retrieval::retrieve_memories/);
  assert.doesNotMatch(permission, /"chat_with_active_model"|"retrieve_memories"/);
  assert.doesNotMatch(permission, /api_credential|model_profile|start_memory_vector_index_rebuild/);
});

test("conversation recovery is SQLite-backed and creates no record until first send", () => {
  const service = read("src/conversation/conversationService.ts");
  const history = read("src/conversation/conversationHistoryService.ts");
  assert.match(service, /history\.list\(\)/);
  assert.match(service, /history\.getMessages\(conversation\.id\)/);
  assert.match(service, /history\.create\("新对话"\)/);
  assert.match(service, /if \(!this\.currentConversation\)/);
  assert.doesNotMatch(service + history, /localStorage|sessionStorage/);
  assert.doesNotMatch(history, /lifeId/);
});

test("settings and main capabilities cannot read conversation content", () => {
  const main = read("src-tauri/permissions/main-commands.toml");
  const settings = read("src-tauri/permissions/settings-commands.toml");
  for (const permission of [main, settings]) {
    assert.doesNotMatch(permission, /get_conversation_messages|list_conversations|chat_with_governed_context/);
  }
});

test("legacy frontend prompt and memory retrieval modules are absent", () => {
  for (const pathName of [
    "src/conversation/memoryContextIntegration.ts",
    "src/memory/context/memoryContextBuilder.ts",
    "src/memory/retrieval/memoryRetrieverService.ts",
    "src/prompt/promptCompiler.ts",
  ]) assert.equal(fs.existsSync(path.join(workspace, pathName)), false);
});
