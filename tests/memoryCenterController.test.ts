import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import type {
  IMemoryManagementService,
  ManagedMemory,
  ManagedMemoryDetail,
  MemoryKind,
  MemoryListRequest,
  MemoryListResult,
  MemoryRevision,
  MemoryStatus,
  UpdateConfirmedMemoryRequest,
  SetMemorySensitiveRequest,
  DeleteMemoryRequest,
  DeleteMemoryResult,
} from "../src/settings/memory/index.ts";
import { MemoryCenterController } from "../src/settings/memory/index.ts";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const workspace = path.resolve(__dirname, "..");
const read = (relativePath: string) =>
  fs.readFileSync(path.join(workspace, relativePath), "utf8");

// ─── Test Helpers ───

function makeMemory(
  id: string,
  overrides: Partial<ManagedMemory> = {},
): ManagedMemory {
  return {
    id,
    status: "confirmed",
    kind: "fact",
    summary: `Summary of ${id}`,
    isSensitive: false,
    revision: 1,
    updatedAt: "2026-07-13T00:00:00Z",
    ...overrides,
  };
}

function makeDetail(
  id: string,
  overrides: Partial<ManagedMemoryDetail> = {},
): ManagedMemoryDetail {
  return {
    ...makeMemory(id),
    content: `Content of ${id}`,
    source: "conversation",
    importance: 0.8,
    confidence: 0.9,
    createdAt: "2026-07-12T00:00:00Z",
    revisionCount: 1,
    ...overrides,
  };
}

function makeRevision(
  revision: number,
  overrides: Partial<MemoryRevision> = {},
): MemoryRevision {
  return {
    revision,
    kind: "fact",
    content: `Content at rev ${revision}`,
    summary: null,
    isSensitive: false,
    changeType: "edited",
    createdAt: "2026-07-13T00:00:00Z",
    ...overrides,
  };
}

function makeMockService(overrides: Partial<IMemoryManagementService> = {}) {
  const defaultService: IMemoryManagementService = {
    async list(): Promise<MemoryListResult> {
      return { items: [], nextCursor: null };
    },
    async get(memoryId: string): Promise<ManagedMemoryDetail> {
      return makeDetail(memoryId);
    },
    async listRevisions(): Promise<MemoryRevision[]> {
      return [];
    },
    async update(request: UpdateConfirmedMemoryRequest): Promise<ManagedMemoryDetail> {
      return makeDetail(request.memoryId, {
        kind: request.kind,
        content: request.content,
        summary: request.summary ?? null,
        revision: 2,
      });
    },
    async setSensitive(request: SetMemorySensitiveRequest): Promise<ManagedMemoryDetail> {
      return makeDetail(request.memoryId, {
        isSensitive: request.isSensitive,
        revision: 2,
      });
    },
    async deletePermanently(request: DeleteMemoryRequest): Promise<DeleteMemoryResult> {
      return { memoryId: request.memoryId, deleted: true };
    },
  };
  return { ...defaultService, ...overrides };
}

// ─── Test: List first load ───

test("list first load populates memories", async () => {
  const items = [makeMemory("m1"), makeMemory("m2")];
  const service = makeMockService({
    async list() {
      return { items, nextCursor: null };
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.refreshList();

  assert.equal(controller.listPhase, "succeeded");
  assert.equal(controller.memories.length, 2);
  assert.equal(controller.memories[0].id, "m1");
  assert.equal(controller.memories[1].id, "m2");
  assert.equal(controller.hasMore, false);
  assert.equal(controller.nextCursor, null);
});

// ─── Test: Filter change clears old cursor and old list ───

test("filter change clears old list and cursor before new request", async () => {
  let callCount = 0;
  const service = makeMockService({
    async list(request: MemoryListRequest) {
      callCount++;
      if (callCount === 1) {
        return {
          items: [makeMemory("old1")],
          nextCursor: { updatedAt: "2026-07-12T00:00:00Z", id: "old1" },
        };
      }
      return { items: [makeMemory("new1")], nextCursor: null };
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.refreshList();
  assert.equal(controller.memories.length, 1);
  assert.equal(controller.memories[0].id, "old1");

  controller.updateFilters({ kind: "preference" });
  // Wait for the async refreshList triggered by updateFilters
  await new Promise((resolve) => setTimeout(resolve, 10));

  assert.equal(controller.memories.length, 1);
  assert.equal(controller.memories[0].id, "new1");
  assert.equal(controller.nextCursor, null);
  assert.equal(controller.filters.kind, "preference");
});

// ─── Test: Load more uses backend cursor and appends ───

test("load more appends results using backend cursor", async () => {
  const cursor = { updatedAt: "2026-07-12T00:00:00Z", id: "m1" };
  let callCount = 0;
  const service = makeMockService({
    async list(request: MemoryListRequest) {
      callCount++;
      if (callCount === 1) {
        return { items: [makeMemory("m1")], nextCursor: cursor };
      }
      assert.deepEqual(request.cursor, cursor);
      return { items: [makeMemory("m2")], nextCursor: null };
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.refreshList();
  assert.equal(controller.hasMore, true);

  await controller.loadMore();
  assert.equal(controller.memories.length, 2);
  assert.equal(controller.memories[0].id, "m1");
  assert.equal(controller.memories[1].id, "m2");
  assert.equal(controller.hasMore, false);
});

// ─── Test: No-change edit does not call update ───

test("no-change edit does not call update", async () => {
  let updateCalled = false;
  const service = makeMockService({
    async update() {
      updateCalled = true;
      return makeDetail("m1");
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.selectMemory("m1");
  controller.openEditForm();

  // Draft matches current detail exactly
  const result = await controller.saveEdit();
  assert.equal(result, true);
  assert.equal(updateCalled, false);
  assert.equal(controller.editDraft, null);
  assert.equal(controller.editPhase, "succeeded");
});

// ─── Test: Normal edit carries expectedRevision ───

test("normal edit carries expectedRevision in request", async () => {
  let capturedRequest: UpdateConfirmedMemoryRequest | null = null;
  const service = makeMockService({
    async update(request) {
      capturedRequest = request;
      return makeDetail("m1", {
        kind: request.kind,
        content: request.content,
        revision: 2,
      });
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.selectMemory("m1");
  assert.equal(controller.detail?.revision, 1);

  controller.openEditForm();
  controller.editDraft!.content = "Updated content";
  const result = await controller.saveEdit();

  assert.equal(result, true);
  assert.ok(capturedRequest);
  assert.equal(capturedRequest.expectedRevision, 1);
  assert.equal(capturedRequest.content, "Updated content");
});

// ─── Test: Edit success refreshes detail and revisions ───

test("edit success refreshes detail and revisions when panel is open", async () => {
  let revisionCalls = 0;
  const service = makeMockService({
    async update(request) {
      return makeDetail("m1", {
        content: request.content,
        revision: 2,
      });
    },
    async listRevisions() {
      revisionCalls++;
      if (revisionCalls === 1) {
        return [makeRevision(1)];
      }
      return [makeRevision(1), makeRevision(2, { changeType: "edited" })];
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.selectMemory("m1");

  // Open revision panel
  await controller.loadRevisions();
  assert.equal(controller.revisions.length, 1);

  // Edit
  controller.openEditForm();
  controller.editDraft!.content = "New content";
  await controller.saveEdit();

  // Revisions should have been refreshed
  assert.equal(revisionCalls, 2);
  assert.equal(controller.revisions.length, 2);
});

// ─── Test: Sensitive toggle carries expectedRevision ───

test("sensitive toggle carries expectedRevision", async () => {
  let capturedRequest: SetMemorySensitiveRequest | null = null;
  const service = makeMockService({
    async setSensitive(request) {
      capturedRequest = request;
      return makeDetail("m1", {
        isSensitive: request.isSensitive,
        revision: 2,
      });
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.selectMemory("m1");

  await controller.toggleSensitive();
  assert.ok(capturedRequest);
  assert.equal(capturedRequest.expectedRevision, 1);
  assert.equal(capturedRequest.isSensitive, true);
});

// ─── Test: Permanent delete requires two-step confirmation ───

test("permanent delete requires two-step confirmation", async () => {
  let deleteCalled = false;
  const service = makeMockService({
    async deletePermanently() {
      deleteCalled = true;
      return { memoryId: "m1", deleted: true };
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.selectMemory("m1");

  // Cannot delete without opening confirm
  assert.equal(controller.deleteConfirmVisible, false);

  // Open confirmation
  controller.openDeleteConfirm();
  assert.equal(controller.deleteConfirmVisible, true);
  assert.equal(deleteCalled, false);

  // Close confirmation
  controller.closeDeleteConfirm();
  assert.equal(controller.deleteConfirmVisible, false);
  assert.equal(deleteCalled, false);

  // Re-open and confirm
  controller.openDeleteConfirm();
  await controller.confirmDelete();
  assert.equal(deleteCalled, true);
  assert.equal(controller.selectedMemoryId, null);
  assert.equal(controller.detail, null);
});

// ─── Test: Delete success removes current list item and clears selection ───

test("delete success clears selection and refreshes list", async () => {
  let listCalls = 0;
  const service = makeMockService({
    async list() {
      listCalls++;
      if (listCalls === 1) {
        return { items: [makeMemory("m1"), makeMemory("m2")], nextCursor: null };
      }
      return { items: [makeMemory("m2")], nextCursor: null };
    },
    async deletePermanently() {
      return { memoryId: "m1", deleted: true };
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.refreshList();
  assert.equal(controller.memories.length, 2);

  await controller.selectMemory("m1");
  controller.openDeleteConfirm();
  await controller.confirmDelete();

  assert.equal(controller.selectedMemoryId, null);
  assert.equal(controller.detail, null);
  assert.equal(controller.memories.length, 1);
  assert.equal(controller.memories[0].id, "m2");
});

// ─── Test: MEMORY_REVISION_CONFLICT preserves local draft ───

test("MEMORY_REVISION_CONFLICT preserves local draft", async () => {
  const service = makeMockService({
    async update() {
      throw {
        code: "MEMORY_REVISION_CONFLICT",
        message: "Revision conflict",
        recoverable: true,
      };
    },
    async get() {
      return makeDetail("m1", { revision: 3, content: "Server version" });
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.selectMemory("m1");

  controller.openEditForm();
  controller.editDraft!.content = "My local draft";

  const result = await controller.saveEdit();
  assert.equal(result, false);
  assert.equal(controller.editPhase, "failed");
  assert.equal(controller.editError?.code, "MEMORY_REVISION_CONFLICT");

  // Draft preserved
  assert.ok(controller.editDraft);
  assert.equal(controller.editDraft.content, "My local draft");
});

// ─── Test: Conflict loads and displays server latest version ───

test("conflict loads server latest version for display", async () => {
  const service = makeMockService({
    async update() {
      throw {
        code: "MEMORY_REVISION_CONFLICT",
        message: "Revision conflict",
        recoverable: true,
      };
    },
    async get() {
      return makeDetail("m1", {
        revision: 3,
        content: "Server version content",
        summary: "Server summary",
      });
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.selectMemory("m1");
  controller.openEditForm();
  controller.editDraft!.content = "My local draft";

  await controller.saveEdit();

  assert.ok(controller.editConflictLatest);
  assert.equal(controller.editConflictLatest.revision, 3);
  assert.equal(controller.editConflictLatest.content, "Server version content");
});

// ─── Test: Accept conflict resolution updates detail and draft ───

test("accept conflict resolution updates detail and draft from server version", async () => {
  const service = makeMockService({
    async update() {
      throw {
        code: "MEMORY_REVISION_CONFLICT",
        message: "Revision conflict",
        recoverable: true,
      };
    },
    async get() {
      return makeDetail("m1", {
        revision: 3,
        content: "Server version",
        kind: "preference",
        summary: "Server summary",
      });
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.selectMemory("m1");
  controller.openEditForm();
  controller.editDraft!.content = "My draft";

  await controller.saveEdit();
  controller.acceptConflictResolution();

  assert.equal(controller.detail?.revision, 3);
  assert.equal(controller.detail?.content, "Server version");
  assert.equal(controller.editDraft?.content, "Server version");
  assert.equal(controller.editDraft?.kind, "preference");
  assert.equal(controller.editDraft?.summary, "Server summary");
  assert.equal(controller.editConflictLatest, null);
  assert.equal(controller.editPhase, "idle");
  assert.equal(controller.editError, undefined);
});

// ─── Test: DTO/Service calls contain no lifeId ───

test("controller never passes lifeId to service calls", async () => {
  const requests: unknown[] = [];
  const service: IMemoryManagementService = {
    async list(request) {
      requests.push(request);
      return { items: [], nextCursor: null };
    },
    async get(memoryId) {
      requests.push({ memoryId });
      return makeDetail(memoryId);
    },
    async listRevisions(memoryId) {
      requests.push({ memoryId });
      return [];
    },
    async update(request) {
      requests.push(request);
      return makeDetail(request.memoryId, { revision: 2 });
    },
    async setSensitive(request) {
      requests.push(request);
      return makeDetail(request.memoryId, { revision: 2 });
    },
    async deletePermanently(request) {
      requests.push(request);
      return { memoryId: request.memoryId, deleted: true };
    },
  };
  const controller = new MemoryCenterController(service);
  await controller.refreshList();
  await controller.selectMemory("m1");
  controller.openEditForm();
  controller.editDraft!.content = "Changed";
  await controller.saveEdit();
  await controller.toggleSensitive();
  controller.openDeleteConfirm();
  await controller.confirmDelete();

  for (const request of requests) {
    const json = JSON.stringify(request);
    assert.doesNotMatch(json, /lifeId/);
    assert.doesNotMatch(json, /life_id/);
  }
});

// ─── Test: Memory Center does not use Chat old commands ───

test("Memory Center source files do not reference Chat commands", () => {
  const files = [
    "src/settings/memory/memoryCenterController.ts",
    "src/settings/memory/MemoryCenterView.vue",
    "src/settings/memory/MemoryListPanel.vue",
    "src/settings/memory/MemoryDetailPanel.vue",
    "src/settings/memory/memoryManagementService.ts",
  ];
  for (const file of files) {
    const source = read(file);
    assert.doesNotMatch(source, /"list_memories"/);
    assert.doesNotMatch(source, /"get_memory"/);
    assert.doesNotMatch(source, /"create_memory_candidate"/);
    assert.doesNotMatch(source, /"update_memory_candidate"/);
    assert.doesNotMatch(source, /"confirm_memory"/);
    assert.doesNotMatch(source, /"delete_memory"/);
  }
});

// ─── Test: No explicit any in task group C files ───

test("task group C files contain no explicit any or ts-ignore", () => {
  const files = [
    "src/settings/memory/memoryCenterController.ts",
    "src/settings/memory/MemoryCenterView.vue",
    "src/settings/memory/MemoryListPanel.vue",
    "src/settings/memory/MemoryDetailPanel.vue",
    "src/settings/memory/index.ts",
    "src/settings/SettingsApp.vue",
  ];
  const anyColonPattern = /:\s*any\b/;
  const asAnyPattern = /\bas\s+any\b/;
  const tsIgnorePattern = new RegExp(String.fromCharCode(64) + "ts-ignore");
  for (const file of files) {
    const source = read(file);
    const lines = source.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const cleanLine = lines[i]
        .replace(/\/\/.*$/, "")
        .replace(/\/\*.*?\*\//g, "");
      assert.doesNotMatch(
        cleanLine,
        anyColonPattern,
        `Found explicit any annotation in ${file} at line ${i + 1}`,
      );
      assert.doesNotMatch(
        cleanLine,
        asAnyPattern,
        `Found type assertion with any in ${file} at line ${i + 1}`,
      );
      assert.doesNotMatch(
        cleanLine,
        tsIgnorePattern,
        `Found ts-ignore directive in ${file} at line ${i + 1}`,
      );
    }
  }
});

// ─── Test: No forbidden fields in task group C files ───

test("task group C files contain no forbidden fields", () => {
  const files = [
    "src/settings/memory/memoryCenterController.ts",
    "src/settings/memory/MemoryCenterView.vue",
    "src/settings/memory/MemoryListPanel.vue",
    "src/settings/memory/MemoryDetailPanel.vue",
    "src/settings/memory/index.ts",
  ];
  for (const file of files) {
    const source = read(file);
    assert.doesNotMatch(source, /\blifeId\b/, `${file} contains lifeId`);
    assert.doesNotMatch(source, /\bvector\b/, `${file} contains vector`);
    assert.doesNotMatch(
      source,
      /\bcontentHash\b/,
      `${file} contains contentHash`,
    );
    assert.doesNotMatch(
      source,
      /\bembedding\b/,
      `${file} contains embedding`,
    );
    assert.doesNotMatch(
      source,
      /\bcredential\b/i,
      `${file} contains credential`,
    );
  }
});

// ─── Test: Stale detail response does not overwrite newer selection ───

test("stale detail response does not overwrite newer selection", async () => {
  let getCallCount = 0;
  const service = makeMockService({
    async get(memoryId: string) {
      getCallCount++;
      if (memoryId === "m1") {
        // Slow response for m1
        await new Promise((resolve) => setTimeout(resolve, 50));
        return makeDetail("m1", { content: "Old memory" });
      }
      return makeDetail(memoryId, { content: "New memory" });
    },
  });
  const controller = new MemoryCenterController(service);

  // Fire both quickly
  const p1 = controller.selectMemory("m1");
  const p2 = controller.selectMemory("m2");
  await Promise.all([p1, p2]);

  // m2 should be shown, not m1
  assert.equal(controller.selectedMemoryId, "m2");
  assert.equal(controller.detail?.content, "New memory");
});

// ─── Test: Load more failure does not clear existing list ───

test("load more failure does not clear existing list", async () => {
  let callCount = 0;
  const service = makeMockService({
    async list() {
      callCount++;
      if (callCount === 1) {
        return {
          items: [makeMemory("m1")],
          nextCursor: { updatedAt: "2026-07-12T00:00:00Z", id: "m1" },
        };
      }
      throw { code: "MEMORY_STORAGE_UNAVAILABLE", message: "DB error", recoverable: true };
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.refreshList();
  assert.equal(controller.memories.length, 1);

  await controller.loadMore();
  // List should still contain m1
  assert.equal(controller.memories.length, 1);
  assert.equal(controller.memories[0].id, "m1");
  assert.ok(controller.listError);
});

// ─── Test: Stale loadMore after filter change is discarded ───

test("stale loadMore after filter change is discarded", async () => {
  let callCount = 0;
  const cursor = { updatedAt: "2026-07-12T00:00:00Z", id: "m1" };
  const service = makeMockService({
    async list(request: MemoryListRequest) {
      callCount++;
      if (callCount === 1) {
        return { items: [makeMemory("m1")], nextCursor: cursor };
      }
      if (callCount === 2) {
        // Slow loadMore
        await new Promise((resolve) => setTimeout(resolve, 50));
        return { items: [makeMemory("m2")], nextCursor: null };
      }
      // Filter change
      return { items: [makeMemory("f1")], nextCursor: null };
    },
  });
  const controller = new MemoryCenterController(service);
  await controller.refreshList();
  assert.equal(controller.memories.length, 1);

  // Start loadMore (slow) then immediately change filter
  const loadMorePromise = controller.loadMore();
  controller.updateFilters({ kind: "preference" });
  await loadMorePromise;
  await new Promise((resolve) => setTimeout(resolve, 60));

  // Should show filter results, not stale loadMore append
  assert.equal(controller.memories.length, 1);
  assert.equal(controller.memories[0].id, "f1");
});
