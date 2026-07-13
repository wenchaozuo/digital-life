import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const settings = fs.readFileSync("src-tauri/permissions/settings-commands.toml", "utf8");
const chat = fs.readFileSync("src-tauri/permissions/chat-commands.toml", "utf8");
const main = fs.readFileSync("src-tauri/permissions/main-commands.toml", "utf8");
const rust = fs.readFileSync("src-tauri/src/lib.rs", "utf8");

const syncCommands = [
  "get_memory_vector_sync_settings",
  "set_memory_vector_sync_enabled",
  "get_memory_vector_sync_status",
  "start_memory_vector_sync",
  "pause_memory_vector_sync",
  "retry_memory_vector_sync_failures",
];

test("vector sync controls are Settings-only", () => {
  for (const command of syncCommands) {
    assert.match(settings, new RegExp(command));
    assert.doesNotMatch(chat, new RegExp(command));
    assert.doesNotMatch(main, new RegExp(command));
  }
});

test("worker state is registered without an application-start execution path", () => {
  assert.match(rust, /MemoryVectorSyncWorkerCoordinator::default/);
  assert.match(rust, /vector_sync_worker::start_memory_vector_sync/);
  const setup = rust.slice(rust.indexOf(".setup("), rust.indexOf(".invoke_handler("));
  assert.doesNotMatch(setup, /start_memory_vector_sync|run_worker|\.drain\(/);
});

test("public sync IPC has no model, credential, memory text, vector, or path parameters", () => {
  const source = fs.readFileSync("src-tauri/src/memory/vector_sync_worker.rs", "utf8");
  const requestSection = source.slice(
    source.indexOf("pub struct MemoryVectorSyncLifeRequest"),
    source.indexOf("pub enum MemoryVectorSyncProcessDisposition"),
  );
  assert.doesNotMatch(
    requestSection,
    /api_key|apiKey|base_url|baseUrl|model_name|modelName|profile_id|profileId|vector_space|memory_content|path/i,
  );
});
