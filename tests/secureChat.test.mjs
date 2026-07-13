import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const workspace = path.resolve(__dirname, "..");

function read(relativePath) {
  return fs.readFileSync(path.join(workspace, relativePath), "utf8");
}

test("chat request DTO contains only user input before cognition builds the model request", () => {
  const conversationTypes = read("src/conversation/types.ts");
  const requestBlock = conversationTypes.match(
    /export interface ConversationRequest \{[\s\S]*?\n\}/,
  )?.[0];

  assert.ok(requestBlock);
  assert.match(requestBlock, /userInput: string/);
  assert.doesNotMatch(
    requestBlock,
    /apiKey|baseUrl|modelName|profileId|providerKind|modelConfig|temperature|maxTokens/,
  );
});

test("model IPC accepts only messages and system context", () => {
  const modelService = read("src/model/modelService.ts");
  const requestBlock = modelService.match(
    /export interface ModelRequest \{[\s\S]*?\n\}/,
  )?.[0];
  const chatMethod = modelService.match(
    /async chat\(request: ModelRequest\)[\s\S]*?\n  \}/,
  )?.[0];

  assert.ok(requestBlock);
  assert.match(requestBlock, /messages: ModelMessage\[\]/);
  assert.match(requestBlock, /systemContext: string \| null/);
  assert.doesNotMatch(
    requestBlock,
    /apiKey|baseUrl|modelName|profileId|providerKind|temperature|maxTokens/,
  );
  assert.ok(chatMethod);
  assert.match(chatMethod, /chat_with_active_model/);
  assert.match(chatMethod, /\{ request \}/);
  assert.doesNotMatch(chatMethod, /config|profileId/);
});

test("ChatView has no runtime model configuration or plaintext credential state", () => {
  const chatView = read("src/chat/ChatView.vue");

  assert.doesNotMatch(
    chatView,
    /apiKey|baseUrl|modelName|Runtime model configuration|type="password"/i,
  );
  assert.match(chatView, /Open model settings/);
  assert.match(chatView, /isSending\.value/);
  assert.match(chatView, /<ChatInput :disabled="isSending"/);
});

test("ConversationService preserves governed context, session, and body-state transitions", () => {
  const service = read("src/conversation/conversationService.ts");

  assert.match(service, /requireCurrentLife\(\)/);
  assert.match(service, /requirePersona\(life\)/);
  assert.match(service, /promptCompiler\.compile\(persona\)/);
  assert.match(service, /prepareConversationMemoryContext/);
  assert.match(service, /this\.dependencies\.model\.chat\(modelRequest\)/);
  assert.match(service, /this\.dependencies\.session\.addMessage\(assistantMessage\)/);
  assert.match(service, /transition\("thinking"\)/);
  assert.match(service, /transition\("speaking"\)/);
  assert.match(service, /transition\("idle"\)/);
  assert.match(service, /transition\("error"\)/);

  const modelCall = service.indexOf(
    "this.dependencies.model.chat(modelRequest)",
  );
  const assistantWrite = service.indexOf(
    "this.dependencies.session.addMessage(assistantMessage)",
  );
  assert.ok(modelCall >= 0 && assistantWrite > modelCall);
});

test("invoke handler and Chat capability expose no plaintext model bypass", () => {
  const rustCommands = read("src-tauri/src/lib.rs");
  const chatPermission = read("src-tauri/permissions/chat-commands.toml");
  const chatCapability = read("src-tauri/capabilities/chat.json");

  assert.match(rustCommands, /model::runtime::chat_with_active_model/);
  assert.doesNotMatch(rustCommands, /model::chat_with_model/);
  assert.match(chatPermission, /"chat_with_active_model"/);
  assert.doesNotMatch(
    chatPermission,
    /api_credential|model_profile|test_model_profile_connection/,
  );
  assert.match(chatCapability, /"chat-commands"/);
  assert.doesNotMatch(chatCapability, /settings-commands|main-commands/);
});
