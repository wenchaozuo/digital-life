import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const workspace = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const read = (relativePath: string) => fs.readFileSync(path.join(workspace, relativePath), "utf8");

test("memory management service exposes only governed Settings commands", () => {
  const source = read("src/settings/memory/memoryManagementService.ts");
  for (const command of [
    "list_managed_memories",
    "get_managed_memory",
    "list_memory_revisions",
    "update_confirmed_memory",
    "set_memory_sensitive",
    "delete_memory_permanently",
  ]) {
    assert.match(source, new RegExp(`"${command}"`));
  }
  assert.doesNotMatch(source, /lifeId|vector|contentHash|leaseOwner|apiKey|databasePath|\bsql\b/i);
});

test("strict DTOs contain Memory Center fields and no storage or credential internals", () => {
  const source = read("src/settings/memory/types.ts");
  for (const expected of [
    "ManagedMemory",
    "ManagedMemoryDetail",
    "MemoryRevision",
    "MemoryListRequest",
    "MemoryListResult",
    "UpdateConfirmedMemoryRequest",
    "SetMemorySensitiveRequest",
    "DeleteMemoryRequest",
    "MemoryManagementError",
  ]) {
    assert.match(source, new RegExp(`interface ${expected}`));
  }
  assert.doesNotMatch(source, /lifeId|vector|contentHash|leaseOwner|apiKey|databasePath|authorization|\bsql\b/i);
  assert.doesNotMatch(source, /\bany\b|as any|@ts-ignore|@ts-expect-error/);
});

test("Settings has Memory Center commands while Chat and main do not", () => {
  const settings = read("src-tauri/permissions/settings-commands.toml");
  const chat = read("src-tauri/permissions/chat-commands.toml");
  const main = read("src-tauri/permissions/main-commands.toml");
  for (const command of [
    "list_managed_memories",
    "get_managed_memory",
    "list_memory_revisions",
    "update_confirmed_memory",
    "set_memory_sensitive",
    "delete_memory_permanently",
  ]) {
    assert.match(settings, new RegExp(`"${command}"`));
    assert.doesNotMatch(chat, new RegExp(`"${command}"`));
    assert.doesNotMatch(main, new RegExp(`"${command}"`));
  }
  assert.doesNotMatch(chat, /"list_memories"/);
  assert.doesNotMatch(chat, /"get_memory"/);
  assert.doesNotMatch(settings, /commands\.allow\s*=\s*\[[^\]]*\*/s);
});

test("Tauri command DTOs resolve current life internally and accept no life override", () => {
  const source = read("src-tauri/src/memory/management.rs");
  for (const requestType of [
    "MemoryIdRequest",
    "UpdateConfirmedMemoryCommandRequest",
    "SetMemorySensitiveCommandRequest",
    "DeleteMemoryCommandRequest",
  ]) {
    const body = source.match(new RegExp(`struct ${requestType} \\{([\\s\\S]*?)\\n\\}`))?.[1];
    assert.ok(body);
    assert.doesNotMatch(body, /life_id/);
  }
  assert.match(source, /get_current_life\(\)/);
});
