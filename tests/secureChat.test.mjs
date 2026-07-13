import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath) => fs.readFileSync(path.join(workspace, relativePath), "utf8");

test("governed chat DTO contains only request id, current message, and committed history", () => {
  const service = read("src/model/modelService.ts");
  const request = service.match(/export interface GovernedConversationRequest \{[\s\S]*?\n\}/)?.[0];
  assert.ok(request);
  assert.match(request, /requestId: string/);
  assert.match(request, /userMessage: string/);
  assert.match(request, /history: GovernedConversationMessage\[\]/);
  assert.doesNotMatch(request, /systemContext|persona|lifeIdentity|memory|apiKey|baseUrl|modelName|profileId|temperature|maxTokens/i);
});

test("frontend uses the governed IPC command without model overrides", () => {
  const service = read("src/model/modelService.ts");
  const method = service.match(/async chatWithGovernedContext\([\s\S]*?\n  \}/)?.[0];
  assert.ok(method);
  assert.match(method, /chat_with_governed_context/);
  assert.doesNotMatch(method, /apiKey|baseUrl|modelName|profileId|systemContext/);
});

test("conversation commits a completed turn atomically after governed success", () => {
  const service = read("src/conversation/conversationService.ts");
  const session = read("src/conversation/session/conversationSession.ts");
  assert.match(service, /chatWithGovernedContext/);
  assert.match(service, /session\.appendTurn\(userMessage, assistantMessage\)/);
  assert.match(service, /transition\("thinking"\)/);
  assert.match(service, /transition\("speaking"\)/);
  assert.match(service, /transition\("error"\)/);
  assert.match(session, /appendTurn\(userMessage: ConversationMessage, assistantMessage: ConversationMessage\)/);
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

test("chat capability adds governed chat while legacy permissions remain until cleanup", () => {
  const rust = read("src-tauri/src/lib.rs");
  const permission = read("src-tauri/permissions/chat-commands.toml");
  assert.match(rust, /conversation::service::chat_with_governed_context/);
  assert.match(rust, /model::runtime::chat_with_active_model/);
  assert.match(permission, /"chat_with_governed_context"/);
  assert.match(permission, /"chat_with_active_model"/);
  assert.doesNotMatch(permission, /api_credential|model_profile|start_memory_vector_index_rebuild/);
});
