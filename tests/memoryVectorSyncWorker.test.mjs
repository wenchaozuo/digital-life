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
  "start_fenced_vector_sync_drain",
  "pause_memory_vector_sync",
  "retry_memory_vector_sync_failures",
];

test("vector sync controls are Settings-only", () => {
  for (const command of syncCommands) {
    assert.match(settings, new RegExp(command));
    assert.doesNotMatch(chat, new RegExp(command));
    assert.doesNotMatch(main, new RegExp(command));
  }
  // The stale legacy background-worker start command must not be granted.
  assert.doesNotMatch(settings, /start_memory_vector_sync/);
  // The fenced production entrypoint is Settings-only.
  assert.doesNotMatch(chat, /start_fenced_vector_sync_drain/);
  assert.doesNotMatch(main, /start_fenced_vector_sync_drain/);
});

test("worker state is registered without an application-start execution path", () => {
  assert.match(rust, /MemoryVectorSyncWorkerCoordinator::default/);
  // The registered production manual-sync entrypoint is the bounded fenced
  // drain; the legacy background-worker start command is NOT registered.
  assert.match(rust, /vector_sync_stage_runtime::start_fenced_vector_sync_drain/);
  assert.doesNotMatch(rust, /vector_sync_worker::start_memory_vector_sync/);
  const setup = rust.slice(rust.indexOf(".setup("), rust.indexOf(".invoke_handler("));
  assert.doesNotMatch(
    setup,
    /start_fenced_vector_sync_drain|run_fenced_vector_sync_drain|start_memory_vector_sync|run_worker|\.drain\(/,
  );
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